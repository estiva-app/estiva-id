/**
 * What `/sign` will and will not sign, per app (PEEK-71).
 *
 * As originally specced, `/sign` is a rubber stamp: hand it anything, get it
 * back signed as the user. A stolen browser token could then rewrite that
 * person's profile, delete their posts, or mint a NIP-98 credential to read the
 * relay directly, bypassing the apps entirely.
 *
 * Two rules matter more than the exact kind lists:
 *
 *   1. **No app may sign kind:0.** The identity service owns profiles; an app
 *      that can publish one can undo that ownership. This is checked before the
 *      per-app allowlist, so it cannot be granted by adding 0 to a row.
 *   2. **NIP-98 (27235) is constrained by URL**, to the relay bridge only.
 *      Otherwise the endpoint mints HTTP credentials for arbitrary destinations.
 *   3. **NIP-42 (22242) is constrained by relay**, for the same reason one kind
 *      over: answering an AUTH challenge is minting a credential to *be* this
 *      user at whichever relay asked. See {@link KIND_RELAY_AUTH}.
 *
 * Everything here is a pure function over a policy and an event, so the rules
 * are testable without a database or a running server.
 */
import type { UnsignedEvent } from '../nostr/event.js'
import { tagValue } from '../nostr/event.js'

/** Profiles belong to the identity service (PEEK-31). Never signable via /sign. */
export const KIND_PROFILE = 0
/** NIP-98 HTTP auth. Signable only for allowlisted URLs. */
export const KIND_HTTP_AUTH = 27235

/**
 * NIP-42 relay auth (PEE-4). Signable only for allowlisted relays.
 *
 * The scope is the whole point of the grant, and it must land with it. A
 * kind:22242 carries the relay's own challenge, so signing one is not
 * publishing a message — it is proving to that relay that this user is present.
 * Granted unqualified, an app that can reach `/sign` can authenticate as the
 * user at *any* relay on the internet, read whatever that relay shows a member,
 * and write as them.
 *
 * Constrained by the `relay` tag, with the same two bounds as NIP-98 above.
 *
 * **Matched exactly after normalization, not by prefix**, which is the one
 * deliberate difference from the 27235 branch. A NIP-98 `u` tag is a full
 * request URL and a prefix is the only workable shape for it. A `relay` tag is
 * a whole relay URL with no path, so a prefix buys nothing and costs something:
 * `wss://estiva.estiva.app` as a prefix also admits
 * `wss://estiva.estiva.app.attacker.example/`. That is the hazard `config.ts`
 * already documents for redirect URIs, and it applies identically here.
 */
export const KIND_RELAY_AUTH = 22242

/**
 * An upstream Buzz artifact save (NIP-AR): every file type shares this kind and
 * names itself in a `type` tag, so the kind alone says nothing about which file
 * an app is saving.
 */
export const KIND_ARTIFACT = 45010

export interface AppPolicy {
  clientId: string
  name: string
  allowedKinds: number[]
  /**
   * The file types this app may save as a `kind:45010`, matched exactly against
   * the event's `type` tag. Empty refuses every type, so a credential granted
   * 45010 without a list signs nothing.
   */
  allowedTypes: string[]
  nip98UrlPrefixes: string[]
  /**
   * Relays this app may answer a NIP-42 challenge from. Deliberately a separate
   * column from `nip98UrlPrefixes` even though both hold the relay's origin
   * today — they are two capabilities, and one list would mean that widening an
   * app's HTTP-bridge access silently widened what it can authenticate to.
   */
  relayAuthUrls: string[]
  status: 'active' | 'disabled'
}

export type PolicyRefusalReason =
  | 'app_disabled'
  | 'kind_profile_forbidden'
  | 'kind_not_allowed'
  | 'type_not_allowed'
  | 'nip98_missing_url'
  | 'nip98_url_not_allowed'
  | 'relay_auth_missing_relay'
  | 'relay_auth_relay_not_allowed'

export type PolicyDecision =
  | { allowed: true }
  | { allowed: false; reason: PolicyRefusalReason; message: string }

const refuse = (reason: PolicyRefusalReason, message: string): PolicyDecision => ({
  allowed: false,
  reason,
  message,
})

/**
 * Canonicalise a relay URL so two spellings of one relay compare equal.
 *
 * `wss://estiva.estiva.app` and `wss://estiva.estiva.app/` are the same relay
 * and both appear in the wild; WHATWG parsing folds them together, along with
 * host case. Returns `undefined` for anything unparseable, which then matches
 * nothing rather than matching another unparseable entry.
 */
function normalizeRelayUrl(raw: string): string | undefined {
  try {
    const parsed = new URL(raw)
    parsed.pathname = parsed.pathname.replace(/\/+$/, '')
    parsed.search = ''
    parsed.hash = ''
    return parsed.toString()
  } catch {
    return undefined
  }
}

/**
 * Decide whether `app` may have `event` signed.
 *
 * `deploymentNip98Prefixes` and `deploymentRelayAuthUrls` are the outer bounds —
 * what this deployment will ever mint NIP-98, or answer a relay challenge, for.
 * An app's own list narrows within each and can never widen it.
 *
 * Both default to empty, so 27235 is refused until somebody decides where the
 * relay bridge lives (PEEK-33), and 22242 until a deployment names its relays.
 * Fail-closed matches Buzz's own posture on `pubkey_allowlist` — and it is why
 * `deploymentRelayAuthUrls` may be defaulted at all: a caller that forgets it
 * refuses relay auth rather than granting it unbounded.
 */
export function evaluateSignPolicy(
  event: UnsignedEvent,
  app: AppPolicy,
  deploymentNip98Prefixes: readonly string[],
  deploymentRelayAuthUrls: readonly string[] = [],
): PolicyDecision {
  if (app.status !== 'active') {
    return refuse('app_disabled', `App ${app.clientId} is disabled`)
  }

  // Checked first and unconditionally: this must not be grantable by editing a
  // row, because the row is the thing an attacker with database access edits.
  if (event.kind === KIND_PROFILE) {
    return refuse(
      'kind_profile_forbidden',
      'kind:0 is published only by the identity service, never through /sign',
    )
  }

  if (!app.allowedKinds.includes(event.kind)) {
    return refuse('kind_not_allowed', `App ${app.clientId} may not sign kind ${event.kind}`)
  }

  // Each app saves only its own file types: Leaf a document, never a project.
  // why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/every-file-is-an-artifact-the-relay-keeps-in-order.md
  if (event.kind === KIND_ARTIFACT) {
    const type = tagValue(event, 'type')
    if (!type || !app.allowedTypes.includes(type)) {
      return refuse(
        'type_not_allowed',
        `App ${app.clientId} may not save a file of type ${type ?? '(none)'}`,
      )
    }
  }

  if (event.kind === KIND_HTTP_AUTH) {
    const url = tagValue(event, 'u')
    if (!url) {
      return refuse('nip98_missing_url', 'A kind 27235 event must carry a "u" tag')
    }

    const allowedByDeployment = deploymentNip98Prefixes.some((prefix) => url.startsWith(prefix))
    const allowedByApp = app.nip98UrlPrefixes.some((prefix) => url.startsWith(prefix))

    if (!allowedByDeployment || !allowedByApp) {
      return refuse(
        'nip98_url_not_allowed',
        'That URL is not an allowed NIP-98 destination for this app',
      )
    }
  }

  if (event.kind === KIND_RELAY_AUTH) {
    const relay = normalizeRelayUrl(tagValue(event, 'relay') ?? '')
    if (!relay) {
      return refuse(
        'relay_auth_missing_relay',
        'A kind 22242 event must carry a "relay" tag holding a valid URL',
      )
    }

    const matches = (allowed: readonly string[]) =>
      allowed.some((candidate) => normalizeRelayUrl(candidate) === relay)

    if (!matches(deploymentRelayAuthUrls) || !matches(app.relayAuthUrls)) {
      return refuse(
        'relay_auth_relay_not_allowed',
        'That relay is not an allowed NIP-42 destination for this app',
      )
    }
  }

  return { allowed: true }
}

/**
 * Whether `app` may use the NIP-44 endpoints (CRO-1).
 *
 * Encryption has no kind to check, so the kind allowlist says nothing about it
 * and the two rules above do not apply. What does apply is the `status` gate:
 * a disabled app must not be able to decrypt, and `/nip44/decrypt` reads what
 * the user has read and when, which is behavioural data about a person.
 *
 * Kept here rather than inline in the route so there is one place that answers
 * "may this app do this", and one refusal vocabulary for a caller to switch on.
 */
export function evaluateEncryptionPolicy(app: AppPolicy): PolicyDecision {
  if (app.status !== 'active') {
    return refuse('app_disabled', `App ${app.clientId} is disabled`)
  }
  return { allowed: true }
}
