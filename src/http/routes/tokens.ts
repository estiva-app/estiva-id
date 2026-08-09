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
 * **Two grants, and both are needed.**
 *
 *   * `authorization_code` with PKCE (PEEK-90) — how an app on another origin
 *     gets a token. The session cookie is `SameSite=Lax` and there is no CORS,
 *     so a cross-origin `fetch` carrying credentials is not merely blocked, it
 *     is blocked twice over. Neither should be relaxed on the origin holding
 *     every custodied key, so the redirect flow is the answer.
 *   * The original session grant — kept, because the account page is served
 *     from this very origin and making it round-trip through a redirect to talk
 *     to its own backend would be ceremony with no security to show for it.
 *
 * The body's shape selects the grant: `{ grantType: 'authorization_code', … }`
 * takes the new path, anything else takes the session path. That keeps the
 * existing callers working unchanged.
 */
import type { Context } from 'hono'
import { Hono } from 'hono'
import { getCookie } from 'hono/cookie'
import { z } from 'zod'
import { config } from '../../config.js'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import { redeemAuthorizationCode } from '../../domain/authorization.js'
import { discoveryDocument, issueToken, publicJwks } from '../../domain/jwt.js'
import { getActivePubkey } from '../../domain/keys.js'
import { SESSION_COOKIE, resolveSession } from '../../domain/sessions.js'
import { findUserById } from '../../domain/users.js'
import { badRequest, forbidden, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'

const sessionGrantSchema = z.object({ clientId: z.string().min(1) })

const codeGrantSchema = z.object({
  grantType: z.literal('authorization_code'),
  code: z.string().min(1),
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  codeVerifier: z.string().min(43).max(128),
})

/** The token body every grant returns. */
function tokenResponse(issued: { token: string; expiresIn: number; pubkey: string }) {
  return {
    access_token: issued.token,
    token_type: 'Bearer',
    expires_in: issued.expiresIn,
    pubkey: issued.pubkey,
    issuer: config().ISSUER_URL,
  }
}

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

  /**
   * The grant is chosen by the body, not by a separate route, so relying
   * parties have one token endpoint to configure — which is also what
   * discovery advertises.
   *
   * `requireSession` cannot be middleware here: the code grant has no session
   * by definition, and a cross-origin caller has no cookie to send.
   */
  routes.post('/token', async (c) => {
    const body: unknown = await c.req.json().catch(() => null)

    const codeGrant = codeGrantSchema.safeParse(body)
    if (codeGrant.success) return exchangeAuthorizationCode(c, codeGrant.data)

    // Not the code grant. If it *looked* like one, say so rather than falling
    // through to a confusing "no session cookie" — a client with a malformed
    // code request has a cookie problem only by coincidence.
    if (typeof body === 'object' && body !== null && 'grantType' in body) {
      throw badRequest('Invalid authorization_code request', {
        issues: codeGrant.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      })
    }

    const token = getCookie(c, SESSION_COOKIE)
    if (!token) throw unauthenticated('No session cookie')
    const session = await resolveSession(token)
    if (!session) throw unauthenticated('Session expired or revoked')
    const { userId } = session

    const parsed = sessionGrantSchema.safeParse(body)
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

    return c.json(tokenResponse(issued))
  })

  /**
   * `grant_type=authorization_code` — the cross-origin path (PEEK-90).
   *
   * Authentication here is the code plus the PKCE verifier, not a cookie. The
   * person proved who they were at `/authorize`; this proves the redeemer is
   * the same app that started the flow.
   *
   * **Every refusal is `invalid_grant` to the caller and specific in the audit
   * log.** Telling a redeemer whether a code was unknown, expired, already
   * used, or matched with the wrong verifier hands an attacker a probe; the
   * distinction matters to us, not to them.
   */
  async function exchangeAuthorizationCode(
    c: Context<AppEnv>,
    input: z.infer<typeof codeGrantSchema>,
  ) {
    const redemption = await redeemAuthorizationCode({
      code: input.code,
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      codeVerifier: input.codeVerifier,
    })

    if (!redemption.ok) {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: input.clientId,
        action: 'token.exchange',
        outcome: 'refused',
        // `already_used` is a replay and worth alerting on one day; the others
        // are ordinary. Recording which is the whole point of a generic reply.
        detail: { reason: redemption.reason },
        requestId: c.get('requestId'),
      })
      throw badRequest('invalid_grant')
    }

    // The app was checked when the code was issued, but a code outlives that
    // check by up to a minute — long enough for an app to be disabled between
    // the two halves of the flow.
    const app = await findAppPolicy(redemption.clientId)
    if (!app || app.status !== 'active') throw forbidden('Unknown or disabled app')

    // Same reason the session grant checks: offboarding must take effect within
    // the JWT TTL, and a code issued a minute ago is not evidence of anything.
    const user = await findUserById(redemption.userId)
    if (!user || user.status !== 'active') {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: app.clientId,
        action: 'token.exchange',
        outcome: 'refused',
        detail: { reason: user ? `user_${user.status}` : 'user_missing' },
        requestId: c.get('requestId'),
      })
      throw forbidden('That identity is no longer active')
    }

    const pubkey = await getActivePubkey(redemption.userId)
    if (!pubkey) throw forbidden('No active key for this identity')

    const issued = await issueToken({ pubkey, clientId: app.clientId })

    await recordAudit({
      actorType: 'app',
      actorUserId: redemption.userId,
      actorClientId: app.clientId,
      action: 'token.exchange',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { expiresIn: issued.expiresIn },
      requestId: c.get('requestId'),
    })

    return c.json(tokenResponse(issued))
  }

  return routes
}
