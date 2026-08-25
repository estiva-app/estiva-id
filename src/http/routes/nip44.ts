/**
 * `POST /nip44/encrypt` and `POST /nip44/decrypt` — self-encryption (CRO-1).
 *
 * NIP-RS keeps a person's read state in a `kind:30078` blob whose content is
 * NIP-44 ciphertext, with the conversation key computed as
 * `nip44_conversation_key(user_privkey, user_pubkey)` — the user encrypting to
 * themselves. That needs the private key, and Peek holds no keys by design
 * (PEEK-40/41). `/sign` was the only seam, and a signature is not encryption.
 *
 * Shaped exactly like `/sign`: bearer token in, operation performed as the
 * token's subject, no key ever leaving the service.
 *
 * ## Self-encryption only, and that is the security argument
 *
 * **Neither endpoint accepts a peer pubkey.** Both operate on
 * `conversation_key(own_priv, own_pub)` and nothing else.
 *
 * The gap between the two designs is large. A *general* `/decrypt` is a
 * decryption oracle: any app holding a token could read anything ever encrypted
 * to that user, including DMs from other people. A **self-only** `/decrypt`
 * reads only what the user encrypted to themselves — today, read-state blobs.
 * That is still behavioural data about a person, which is why the rate limit and
 * the audit rows below are here from the start rather than added later.
 *
 * Widening this is a deliberate decision with its own review. Starting general
 * and narrowing later does not happen.
 *
 * The request schemas are **`.strict()`**, so a caller that sends `pubkey` or
 * `peer` gets a 400 rather than having it ignored. `/sign` ignores a supplied
 * pubkey because there the authoritative one is unambiguous — you always get
 * your own signature, which is what you wanted. Here, ignoring it would hand
 * back a self-encrypted blob to an app that believed it was encrypting to
 * somebody else, and the mistake would surface as an undecryptable message on
 * the far side, days later. Refusing says so at the call.
 *
 * ## Cross-origin
 *
 * Peek is a browser app on another origin, so these are preflighted exactly as
 * `/sign` is — see the note in `sign.ts` and the safety argument in
 * `http/cors.ts`. The header goes on refusals too, for the same reason: a 429 a
 * browser will not let the app read becomes an indistinguishable network error.
 */
import { type Context, Hono } from 'hono'
import { z } from 'zod'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import { verifyToken } from '../../domain/jwt.js'
import { findSignerByPubkey, withUserSecretKey } from '../../domain/keys.js'
import { evaluateEncryptionPolicy } from '../../domain/policy.js'
import {
  badRequest,
  forbidden,
  policyViolation,
  rateLimited,
  unauthenticated,
} from '../../errors.js'
import {
  MAX_PLAINTEXT_BYTES,
  Nip44Error,
  conversationKey,
  decrypt,
  encrypt,
} from '../../nostr/nip44.js'
import type { AppEnv } from '../app.js'
import { allowOrigin, preflight } from '../cors.js'
import { createRateLimiter } from '../rate-limit.js'

/**
 * 120 operations per minute, per app, per person.
 *
 * Sized against the real caller rather than picked round: marking a container
 * read is one encrypt, and Peek's read-state writes are debounced, so a busy
 * person generates single digits per minute. Two orders of magnitude of
 * headroom leaves normal use untouched while still bounding what a leaked
 * ten-minute token can pull through `/decrypt` — roughly 1,200 blobs rather
 * than as many as the network allows.
 *
 * Shared between encrypt and decrypt, keyed on `(clientId, pubkey)`. One budget
 * because the pair is one capability: a limit that let decrypt run at full rate
 * as long as encrypt was idle would bound nothing.
 */
const RATE_LIMIT_PER_MINUTE = 120

const limiter = createRateLimiter(RATE_LIMIT_PER_MINUTE, 60_000)

/** Test seam — see `rate-limit.ts`. Not reachable over HTTP. */
export const resetRateLimitForTests = () => limiter.reset()

// `.strict()` is load-bearing, not tidiness — see the header.
const encryptSchema = z.object({ plaintext: z.string() }).strict()
const decryptSchema = z.object({ ciphertext: z.string() }).strict()

function bearerToken(header: string | undefined): string {
  if (!header?.startsWith('Bearer ')) throw unauthenticated('Expected a Bearer token')
  const token = header.slice('Bearer '.length).trim()
  if (!token) throw unauthenticated('Empty Bearer token')
  return token
}

type Operation = 'encrypt' | 'decrypt'

interface Caller {
  userId: string
  pubkey: string
  clientId: string
}

/**
 * Everything both endpoints do before they touch a key.
 *
 * Lifted out rather than copied because it is the authorization path: two
 * copies of it would be one implementation and one liability, which is the same
 * argument `cors.ts` makes about itself.
 */
async function authorize(c: Context<AppEnv>, operation: Operation): Promise<Caller> {
  const requestId = c.get('requestId')
  const { pubkey, clientId } = await verifyToken(bearerToken(c.req.header('authorization')))

  const refuse = async (reason: string, userId?: string) => {
    await recordAudit({
      actorType: 'app',
      actorUserId: userId,
      actorClientId: clientId,
      action: `nip44.${operation}.refused`,
      outcome: 'refused',
      subjectPubkey: pubkey,
      detail: { reason },
      requestId,
    })
  }

  const app = await findAppPolicy(clientId)
  if (!app) {
    await refuse('unknown_app')
    throw forbidden('Unknown app credential')
  }

  // The token's subject is the only identity this call may act as. Resolving it
  // back to a user is also what makes a token for a deleted or rotated key fail
  // rather than use a stale one.
  const signer = await findSignerByPubkey(pubkey)
  if (!signer) {
    await refuse('no_active_key')
    throw forbidden('No active key for that identity')
  }

  // The person, not the key — the same offboarding seam `/sign` documents.
  // Tokens are stateless and live for JWT_TTL_SECONDS, so this is the only
  // point at which offboarding takes effect on this path.
  if (signer.userStatus !== 'active') {
    await refuse(`user_${signer.userStatus}`, signer.userId)
    throw forbidden('That identity is no longer active')
  }

  // No kind to check here, so this is the `status` gate and the shared refusal
  // vocabulary — a disabled app must not be able to decrypt.
  const decision = evaluateEncryptionPolicy(app)
  if (!decision.allowed) {
    await refuse(decision.reason, signer.userId)
    throw policyViolation(decision.message, { reason: decision.reason })
  }

  const budget = limiter.check(`${clientId}:${pubkey}`)
  if (!budget.allowed) {
    await refuse('rate_limited', signer.userId)
    c.header('retry-after', String(budget.retryAfterSeconds))
    throw rateLimited('Too many encryption requests', {
      reason: 'rate_limited',
      retryAfterSeconds: budget.retryAfterSeconds,
    })
  }

  return { userId: signer.userId, pubkey, clientId }
}

/** Never the plaintext, never the ciphertext — only that it happened. */
async function recordGranted(
  c: Context<AppEnv>,
  caller: Caller,
  operation: Operation,
): Promise<void> {
  await recordAudit({
    actorType: 'app',
    actorUserId: caller.userId,
    actorClientId: caller.clientId,
    action: `nip44.${operation}.granted`,
    outcome: 'success',
    subjectPubkey: caller.pubkey,
    detail: {},
    requestId: c.get('requestId'),
  })
}

export function nip44Routes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.options('/nip44/encrypt', preflight('POST, OPTIONS', 'authorization, content-type'))
  routes.options('/nip44/decrypt', preflight('POST, OPTIONS', 'authorization, content-type'))

  routes.post('/nip44/encrypt', async (c) => {
    // Before anything that can throw, so a refusal is readable by the app that
    // was refused.
    await allowOrigin(c)
    const caller = await authorize(c, 'encrypt')

    const parsed = encryptSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) {
      throw badRequest('Expected { plaintext } and no other field', {
        issues: parsed.error.issues,
      })
    }

    const ciphertext = await withUserSecretKey(caller.userId, (secretKey, pubkey) =>
      // `pubkey` is the key's own public half, read from the row alongside the
      // secret. Self-encryption is not a special case of ECDH, it is ECDH with
      // both halves of one keypair — so there is no peer to get wrong.
      encrypt(parsed.data.plaintext, conversationKey(secretKey, pubkey)),
    ).catch((error: unknown) => {
      // Length bounds live in the NIP, not in zod, so this is where an
      // over-long plaintext surfaces. 1..65535 *bytes* of UTF-8.
      if (error instanceof Nip44Error) {
        throw badRequest(`Plaintext must be 1 to ${MAX_PLAINTEXT_BYTES} bytes of UTF-8`, {
          reason: 'invalid_plaintext',
        })
      }
      throw error
    })

    await recordGranted(c, caller, 'encrypt')
    return c.json({ ciphertext })
  })

  routes.post('/nip44/decrypt', async (c) => {
    await allowOrigin(c)
    const caller = await authorize(c, 'decrypt')

    const parsed = decryptSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) {
      throw badRequest('Expected { ciphertext } and no other field', {
        issues: parsed.error.issues,
      })
    }

    let failure: string | undefined
    const plaintext = await withUserSecretKey(caller.userId, (secretKey, pubkey) =>
      decrypt(parsed.data.ciphertext, conversationKey(secretKey, pubkey)),
    ).catch((error: unknown) => {
      if (!(error instanceof Nip44Error)) throw error
      failure = error.message
      return undefined
    })

    if (plaintext === undefined) {
      // One message for every failure, whatever went wrong. Distinguishing a
      // bad MAC from bad padding to the caller is the classic padding-oracle
      // shape; the specific reason goes to the audit row, where it is useful
      // and not reachable by whoever is probing.
      await recordAudit({
        actorType: 'app',
        actorUserId: caller.userId,
        actorClientId: caller.clientId,
        action: 'nip44.decrypt.refused',
        outcome: 'refused',
        subjectPubkey: caller.pubkey,
        detail: { reason: 'undecryptable', failure },
        requestId: c.get('requestId'),
      })
      throw badRequest('Could not decrypt that ciphertext', { reason: 'undecryptable' })
    }

    await recordGranted(c, caller, 'decrypt')
    return c.json({ plaintext })
  })

  return routes
}
