/**
 * Token issuance and discovery (PEEK-29).
 *
 *   * `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json`
 *     — what a relying party resolves. `convex/auth.config.ts` takes a `domain`
 *     plus an `applicationID` and finds JWKS from discovery, the same way a
 *     Clerk or Auth0 integration does.
 *   * `POST /token` — the browser-side handoff, in its minimal form: exchange a
 *     session on this origin for a short-lived JWT scoped to one app.
 *
 * The full cross-origin redirect flow is deliberately not here. Nothing
 * consumes it until Stage 2, and building an authorization-code dance before
 * there is a client to test it against would be guessing at a contract.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import { discoveryDocument, issueToken, publicJwks } from '../../domain/jwt.js'
import { getActivePubkey } from '../../domain/keys.js'
import { findUserById } from '../../domain/users.js'
import { badRequest, forbidden } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { requireSession } from '../middleware/session.js'

const tokenRequestSchema = z.object({ clientId: z.string().min(1) })

export function tokenRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.get('/.well-known/openid-configuration', (c) => {
    // Cacheable: relying parties fetch this on cold start and it changes only
    // when the issuer does.
    c.header('cache-control', 'public, max-age=300')
    return c.json(discoveryDocument())
  })

  routes.get('/.well-known/jwks.json', async (c) => {
    c.header('cache-control', 'public, max-age=300')
    return c.json(await publicJwks())
  })

  routes.post('/token', requireSession, async (c) => {
    const { userId } = c.get('session')
    const parsed = tokenRequestSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) throw badRequest('Expected { clientId }')

    // Tokens are audience-bound, so an unknown or disabled app must not get one
    // — otherwise /sign would be deciding policy for an app that does not exist.
    const app = await findAppPolicy(parsed.data.clientId)
    if (!app || app.status !== 'active') throw forbidden('Unknown or disabled app')

    // Sessions outlive an offboarding unless something revokes them, and a
    // session is all `/token` needs. Checking the person here is what stops a
    // leaver refreshing their way past the JWT expiry indefinitely.
    const user = await findUserById(userId)
    if (!user || user.status !== 'active') {
      await recordAudit({
        actorType: 'user',
        actorUserId: userId,
        actorClientId: parsed.data.clientId,
        action: 'token.issue',
        outcome: 'refused',
        detail: { reason: user ? `user_${user.status}` : 'user_missing' },
        requestId: c.get('requestId'),
      })
      throw forbidden('That identity is no longer active')
    }

    const pubkey = await getActivePubkey(userId)
    if (!pubkey) throw forbidden('No active key for this identity')

    const issued = await issueToken({ pubkey, clientId: app.clientId })

    await recordAudit({
      actorType: 'user',
      actorUserId: userId,
      actorClientId: app.clientId,
      action: 'token.issue',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { expiresIn: issued.expiresIn },
      requestId: c.get('requestId'),
    })

    return c.json({
      access_token: issued.token,
      token_type: 'Bearer',
      expires_in: issued.expiresIn,
      pubkey: issued.pubkey,
      issuer: config().ISSUER_URL,
    })
  })

  return routes
}
