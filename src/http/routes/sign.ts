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
 *
 * ## Cross-origin (PEEK-93)
 *
 * The callers are browser apps on other origins — Ship's `estivaIdSigner` does
 * `fetch(origin + '/sign')` with a Bearer header, which is **preflighted**. This
 * route shipped without an `OPTIONS` handler, so the browser never sent the
 * POST and every signed action failed with a generic network error. Ship is a
 * static bundle with no backend, so there was nowhere else for the call to come
 * from.
 *
 * That is the PEEK-90 bug a second time, and it stayed invisible for the same
 * reason: **nothing enforces CORS when a Hono app is called in-process**, so a
 * full suite of passing tests says nothing about whether a browser can use this.
 *
 * The safety argument is unchanged from `/token` — see `http/cors.ts`. The
 * allowlist is the registered redirect URIs, and `Allow-Credentials` is never
 * sent, so the session cookie still cannot be used from another origin. `/sign`
 * authenticates with a bearer token the caller already holds and sends
 * explicitly; no ambient authority is shared by letting it read the reply.
 *
 * **The header goes on refusals too**, deliberately. A `policy_violation` that a
 * browser will not let the app read turns "this app may not sign that kind"
 * into "network error", which is the failure mode this endpoint's careful
 * `detail.reason` vocabulary exists to avoid.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import { checkDelegation, withDelegateTag } from '../../domain/delegation.js'
import { verifyToken } from '../../domain/jwt.js'
import { findSignerByPubkey, withUserSecretKey } from '../../domain/keys.js'
import { evaluateSignPolicy } from '../../domain/policy.js'
import { badRequest, forbidden, policyViolation, unauthenticated } from '../../errors.js'
import { signEvent } from '../../nostr/keys.js'
import type { AppEnv } from '../app.js'
import { allowOrigin, preflight } from '../cors.js'

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

  routes.options('/sign', preflight('POST, OPTIONS', 'authorization, content-type'))

  routes.post('/sign', async (c) => {
    const cfg = config()
    const requestId = c.get('requestId')

    // Before anything that can throw, so a refusal is readable by the app that
    // was refused. Sets the header only for a registered origin; a same-origin
    // caller sends no Origin and needs none.
    await allowOrigin(c)

    const { pubkey, clientId, delegate } = await verifyToken(
      bearerToken(c.req.header('authorization')),
    )

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

    /*
      A bot signing as this person (PER-22). Re-checked on every call rather
      than trusted from the token, which is what makes revoking a delegation
      stop the next signature instead of the one after the token expires.
    */
    let delegateTag: string | undefined
    if (delegate) {
      const check = await checkDelegation(delegate)
      if (!check.ok || check.userId !== userId) {
        await recordAudit({
          actorType: 'app',
          actorUserId: userId,
          actorClientId: clientId,
          action: 'sign.refused',
          outcome: 'refused',
          subjectPubkey: pubkey,
          detail: {
            reason: check.ok ? 'delegation_unknown' : check.reason,
            delegate: delegate.clientId,
            kind: parsed.data.event.kind,
          },
          requestId,
        })
        throw unauthenticated('That delegation has ended')
      }
      delegateTag = check.tag
    }

    const unsigned = {
      pubkey,
      kind: parsed.data.event.kind,
      created_at: parsed.data.event.created_at ?? Math.floor(Date.now() / 1000),
      tags: delegateTag
        ? withDelegateTag(parsed.data.event.tags, delegateTag)
        : parsed.data.event.tags,
      content: parsed.data.event.content,
    }

    const decision = evaluateSignPolicy(
      unsigned,
      app,
      cfg.SIGN_NIP98_ALLOWED_URL_PREFIXES,
      cfg.SIGN_RELAY_AUTH_ALLOWED_URLS,
    )
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
      detail: {
        kind: signed.kind,
        eventId: signed.id,
        // The bot, when one signed as this person — so "what did the agent
        // publish as me" is one query on `detail->>'delegate'`.
        ...(delegate ? { delegate: delegate.clientId, tag: delegateTag } : {}),
      },
      requestId,
    })

    return c.json({ event: signed })
  })

  return routes
}
