/**
 * NIP-OA — owner attestation, from the side that holds the owner's key.
 *
 * A tag proving that one key (the **owner**) authorised another key (the
 * **agent**) to act. Buzz stores the result in `users.agent_owner_pubkey` and
 * uses it for real authorisation: deleting a group, removing a member, and
 * telling an agent's post apart from a person's.
 *
 * Estiva ID is the only party that can produce one of these. The owner is a
 * human whose key it custodies, and the agent is a role identity it also
 * custodies — so the attestation is a statement it is uniquely placed to make,
 * and `users.owner_user_id` (migration 008) is where it already knows the
 * answer.
 *
 * ## The wire format
 *
 * ```json
 * ["auth", "<owner-pubkey-hex>", "<conditions>", "<sig-hex>"]
 * ```
 *
 * ```text
 * preimage = "nostr:agent-auth:" || agent_pubkey_hex || ":" || conditions
 * message  = SHA256(preimage)
 * sig      = BIP-340 Schnorr(message, owner_secret_key)
 * ```
 *
 * **The owner signs a statement naming the agent's key**, which is what makes
 * it unforgeable by the agent: the agent's own signature over the same bytes
 * proves nothing, and the relay rejects `owner == agent` outright.
 *
 * Note the shape of the digest. This is *not* a Nostr event — there is no id,
 * no `created_at`, no serialisation array. It is a bare SHA-256 of an ASCII
 * string, signed directly. `nostr/keys.ts:signEvent` cannot produce it, which
 * is why this module exists rather than reusing that path.
 *
 * ## Why the conditions string is validated here
 *
 * Buzz's verifier (`crates/buzz-sdk/src/nip_oa.rs`) revalidates `conditions`
 * *after* checking the signature, so a malformed one produces a tag that is
 * cryptographically perfect and refused anyway — the least debuggable failure
 * available. Rejecting it at signing time turns that into an error next to the
 * code that chose the value.
 */
import { schnorr } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils'

/** The NIP-OA `auth` tag, as it travels: label, owner, conditions, signature. */
export type AuthTag = ['auth', string, string, string]

/**
 * Validate a `conditions` string exactly as Buzz's `validate_conditions` does.
 *
 * Empty is valid and means "no constraint". Otherwise it is one or more clauses
 * joined by `&`, each `kind=<0-65535>`, `created_at<<n>` or `created_at><n>`
 * with `n` a canonical decimal (no leading zeros) up to 4294967295. No
 * whitespace anywhere.
 *
 * Throws rather than returning a boolean: every caller here would only turn a
 * `false` into a throw, and a silently-unsigned attestation is worse than none.
 */
export function assertValidConditions(conditions: string): void {
  if (conditions === '') return
  if (/\s/.test(conditions)) throw new Error('NIP-OA conditions must not contain whitespace')

  for (const clause of conditions.split('&')) {
    if (clause === '') {
      throw new Error(`NIP-OA conditions has an empty clause: ${JSON.stringify(conditions)}`)
    }
    const match = /^(kind=|created_at<|created_at>)(\d+)$/.exec(clause)
    if (!match)
      throw new Error(`NIP-OA conditions has an unsupported clause: ${JSON.stringify(clause)}`)

    const label = match[1] as string
    const digits = match[2] as string
    // Canonical decimals only. "09" and "0000" verify as numbers and are
    // refused by the relay, so accepting them here would ship a tag that
    // cannot be used.
    if (digits.length > 1 && digits.startsWith('0')) {
      throw new Error(`NIP-OA conditions has a leading zero: ${JSON.stringify(clause)}`)
    }
    const max = label === 'kind=' ? 65535 : 4294967295
    if (Number(digits) > max) {
      throw new Error(
        `NIP-OA conditions value out of range for ${label}: ${JSON.stringify(clause)}`,
      )
    }
  }
}

const HEX64 = /^[0-9a-f]{64}$/

/** The bytes the owner signs. Exported so a test can pin it against the spec. */
export function authPreimage(agentPubkey: string, conditions: string): string {
  return `nostr:agent-auth:${agentPubkey}:${conditions}`
}

/**
 * Sign an attestation that `agentPubkey` is owned by the holder of `ownerSecretKey`.
 *
 * `conditions` defaults to `''` — no constraint. A `kind=` clause would narrow
 * the attestation to one event kind, which is not what this is for: the
 * relationship being recorded is *who steers this agent*, and it does not vary
 * by kind. Buzz stores the owner and never re-reads the conditions, so
 * narrowing here would buy nothing and could only bite later.
 *
 * The owner's pubkey is **derived from the secret**, never taken as a
 * parameter — the same rule `signEvent` follows, and for the same reason: a
 * caller cannot ask for an attestation naming somebody else.
 */
export function computeAuthTag(
  ownerSecretKey: Buffer | Uint8Array,
  agentPubkey: string,
  conditions = '',
): AuthTag {
  if (!HEX64.test(agentPubkey)) {
    throw new Error('NIP-OA agent pubkey must be 64 lowercase hex characters')
  }
  assertValidConditions(conditions)

  const ownerPubkey = bytesToHex(schnorr.getPublicKey(ownerSecretKey))
  // Rejected by the relay as meaningless, and it is: a key vouching for itself
  // proves only that it exists. Caught here so it surfaces as a configuration
  // error rather than a relay refusal three hops away.
  if (ownerPubkey === agentPubkey) {
    throw new Error('NIP-OA owner and agent pubkeys must differ (self-attestation is rejected)')
  }

  const digest = sha256(utf8ToBytes(authPreimage(agentPubkey, conditions)))
  const sig = bytesToHex(schnorr.sign(digest, ownerSecretKey))
  return ['auth', ownerPubkey, conditions, sig]
}

/**
 * Verify one, returning the owner pubkey it proves.
 *
 * Not needed to publish — Buzz does the verifying that matters. It is here so
 * this module's own tests can prove a tag round-trips, and so a caller can
 * check a tag it did not make without reaching for the curve library.
 */
export function verifyAuthTag(tag: unknown, agentPubkey: string): string {
  if (!Array.isArray(tag) || tag.length !== 4) {
    throw new Error('NIP-OA auth tag must have exactly 4 elements')
  }
  const [label, ownerPubkey, conditions, sig] = tag as unknown[]
  if (label !== 'auth') throw new Error('NIP-OA auth tag must start with "auth"')
  if (typeof ownerPubkey !== 'string' || !HEX64.test(ownerPubkey)) {
    throw new Error('NIP-OA owner pubkey must be 64 lowercase hex characters')
  }
  if (typeof conditions !== 'string') throw new Error('NIP-OA conditions must be a string')
  if (typeof sig !== 'string' || !/^[0-9a-f]{128}$/.test(sig)) {
    throw new Error('NIP-OA signature must be 128 lowercase hex characters')
  }
  assertValidConditions(conditions)
  if (ownerPubkey === agentPubkey) {
    throw new Error('NIP-OA owner and agent pubkeys must differ (self-attestation is rejected)')
  }

  const digest = sha256(utf8ToBytes(authPreimage(agentPubkey, conditions)))
  if (!schnorr.verify(sig, digest, ownerPubkey)) {
    throw new Error('NIP-OA signature verification failed')
  }
  return ownerPubkey
}

/** The header Buzz reads an attestation from on its HTTP bridge. */
export const AUTH_TAG_HEADER = 'x-auth-tag'

/** How the tag travels in {@link AUTH_TAG_HEADER} — the raw JSON array. */
export function authTagHeaderValue(tag: AuthTag): string {
  return JSON.stringify(tag)
}
