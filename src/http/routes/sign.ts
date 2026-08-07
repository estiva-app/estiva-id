/**
 * `POST /sign` — the remote signing seam (PEEK-28).
 *
 * An app posts an unsigned event with the user's token and gets it back signed.
 * No app ever holds a secret key.
 *
 * This is NIP-46's property over HTTPS instead of relay transport. Real NIP-46
 * needs a socket for kind:24133 traffic, and Convex functions are
 * request-scoped and cannot hold one — `convex/nostr/sync.ts` already polls for
 * exactly that reason. Signing latency in seconds would be unusable on a click.
 *
 * **Stage 4 re-points this seam at a local signer**, so the request/response
 * contract matters more than what is behind it today. The contract is:
 *
 *     POST /sign
 *     Authorization: Bearer <jwt issued to this app for this user>
 *     { "event": { kind, created_at, tags, content } }
 *
 *     200 { "event": { id, pubkey, kind, created_at, tags, content, sig } }
 *
 * `pubkey` is ignored on input and always set from the authenticated user's
 * key. A caller does not choose whose signature it gets.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import { verifyToken } from '../../domain/jwt.js'
import { findSignerByPubkey, withUserSecretKey } from '../../domain/keys.js'
import { evaluateSignPolicy } from '../../domain/policy.js'
import { badRequest, forbidden, policyViolation, unauthenticated } from '../../errors.js'
import { signEvent } from '../../nostr/keys.js'
import type { AppEnv } from '../app.js'

const unsignedEventSchema = z.object({
  kind: z.number().int().min(0).max(65535),
  created_at: z.number().int().positive().optional(),
  tags: z.array(z.array(z.string())).default([]),
  content: z.string().default(''),
  // Accepted and ignored — the server always signs as the authenticated user.
  pubkey: z.string().optional(),
})

const signRequestSchema = z.object({ event: unsignedEventSchema })

function bearerToken(header: string | undefined): string {
  if (!header?.startsWith('Bearer ')) throw unauthenticated('Expected a Bearer token')
  const token = header.slice('Bearer '.length).trim()
  if (!token) throw unauthenticated('Empty Bearer token')
  return token
}

export function signRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.post('/sign', async (c) => {
    const cfg = config()
    const requestId = c.get('requestId')

    const { pubkey, clientId } = await verifyToken(bearerToken(c.req.header('authorization')))

    const parsed = signRequestSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) {
      throw badRequest('Expected { event: { kind, tags, content } }', {
        issues: parsed.error.issues,
      })
    }

    const app = await findAppPolicy(clientId)
    if (!app) {
      await recordAudit({
        actorType: 'app',
        actorClientId: clientId,
        action: 'sign.refused',
        outcome: 'refused',
        subjectPubkey: pubkey,
        detail: { reason: 'unknown_app', kind: parsed.data.event.kind },
        requestId,
      })
      throw forbidden('Unknown app credential')
    }

    // The token's subject is the only pubkey this call may sign as. Resolving it
    // back to a user is also what makes a token for a deleted or rotated key
    // fail rather than sign with a stale one.
    const signer = await findSignerByPubkey(pubkey)
    if (!signer) {
      await recordAudit({
        actorType: 'app',
        actorClientId: clientId,
        action: 'sign.refused',
        outcome: 'refused',
        subjectPubkey: pubkey,
        detail: { reason: 'no_active_key', kind: parsed.data.event.kind },
        requestId,
      })
      throw forbidden('No active key for that identity')
    }

    // The person, not the key. Tokens are stateless and live for JWT_TTL_SECONDS,
    // so this is the only point at which an offboarding can take effect on the
    // signing path — without it a leaver kept signing indefinitely, because
    // offboarding sets `users.status` and never touches their key.
    if (signer.userStatus !== 'active') {
      await recordAudit({
        actorType: 'app',
        actorUserId: signer.userId,
        actorClientId: clientId,
        action: 'sign.refused',
        outcome: 'refused',
        subjectPubkey: pubkey,
        detail: { reason: `user_${signer.userStatus}`, kind: parsed.data.event.kind },
        requestId,
      })
      throw forbidden('That identity is no longer active')
    }
    const userId = signer.userId

    const unsigned = {
      pubkey,
      kind: parsed.data.event.kind,
      created_at: parsed.data.event.created_at ?? Math.floor(Date.now() / 1000),
      tags: parsed.data.event.tags,
      content: parsed.data.event.content,
    }

    const decision = evaluateSignPolicy(unsigned, app, cfg.SIGN_NIP98_ALLOWED_URL_PREFIXES)
    if (!decision.allowed) {
      // "Done when: an app asking to sign a kind outside its list is refused,
      // and the refusal is logged."
      await recordAudit({
        actorType: 'app',
        actorUserId: userId,
        actorClientId: clientId,
        action: 'sign.refused',
        outcome: 'refused',
        subjectPubkey: pubkey,
        detail: { reason: decision.reason, kind: unsigned.kind },
        requestId,
      })
      throw policyViolation(decision.message, { reason: decision.reason })
    }

    const signed = await withUserSecretKey(userId, (secretKey) => signEvent(unsigned, secretKey))

    await recordAudit({
      actorType: 'app',
      actorUserId: userId,
      actorClientId: clientId,
      action: 'sign.granted',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { kind: signed.kind, eventId: signed.id },
      requestId,
    })

    return c.json({ event: signed })
  })

  return routes
}
