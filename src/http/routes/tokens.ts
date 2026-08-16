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
 *     gets a token. The session cookie is `SameSite=Lax`, so it is not sent on
 *     a cross-site `fetch` at all; relaxing that on the origin holding every
 *     custodied key is not worth it, so the redirect flow is the answer.
 *
 *     This endpoint *does* send CORS headers, and that is not a contradiction:
 *     they carry no `Allow-Credentials`, so the cookie still cannot be used
 *     from another origin. What they permit is a public client reading the
 *     response to a request it authenticated with a code and a PKCE verifier —
 *     credentials it already holds. Discovering that distinction cost one
 *     failed exchange; see the middleware below.
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
import { issueRefreshToken, redeemRefreshToken } from '../../domain/refresh.js'
import { authenticateServiceCredential } from '../../domain/roles.js'
import { SESSION_COOKIE, resolveSession } from '../../domain/sessions.js'
import { findUserById } from '../../domain/users.js'
import { badRequest, forbidden, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { allowOrigin, preflight } from '../cors.js'

const sessionGrantSchema = z.object({ clientId: z.string().min(1) })

const codeGrantSchema = z.object({
  grantType: z.literal('authorization_code'),
  code: z.string().min(1),
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  codeVerifier: z.string().min(43).max(128),
})

/**
 * The client-credentials grant, for role identities (PEEK-34).
 *
 * No `redirectUri` and no `codeVerifier`: there is no browser and no person to
 * send anywhere. The app *is* the principal's custodian, which is exactly why
 * it must present a secret — and why only a server-side client may hold one.
 */
const serviceGrantSchema = z.object({
  grantType: z.literal('client_credentials'),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
})

/**
 * The refresh grant (PEEK-108).
 *
 * No secret and no verifier: a public client has neither. The refresh token
 * *is* the credential, which is why it rotates on every use and why presenting
 * a spent one revokes the whole chain — see `domain/refresh.ts`.
 */
const refreshGrantSchema = z.object({
  grantType: z.literal('refresh_token'),
  refreshToken: z.string().min(1),
  clientId: z.string().min(1),
})

/**
 * The token body every grant returns.
 *
 * `refresh_token` is present only where one was minted — the code and refresh
 * grants. The session grant is same-origin and the client-credentials grant has
 * a secret it can present again, so neither needs one, and issuing a long-lived
 * credential to a caller with no use for it is pure downside.
 */
function tokenResponse(
  issued: { token: string; expiresIn: number; pubkey: string },
  refreshToken?: string,
) {
  return {
    access_token: issued.token,
    token_type: 'Bearer',
    expires_in: issued.expiresIn,
    pubkey: issued.pubkey,
    issuer: config().ISSUER_URL,
    ...(refreshToken ? { refresh_token: refreshToken } : {}),
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
   * The code grant is used by a **public client in a browser on another
   * origin**, so the browser has to be allowed to read the response. Without
   * this the redirect completes, the code comes back, and the exchange dies at
   * the preflight — which is exactly what happened the first time Ship tried it.
   *
   * The rules, and why the session grant stays same-origin-only regardless, are
   * in `http/cors.ts`.
   */
  routes.options('/token', preflight('POST, OPTIONS', 'content-type'))

  /**
   * The grant is chosen by the body, not by a separate route, so relying
   * parties have one token endpoint to configure — which is also what
   * discovery advertises.
   *
   * `requireSession` cannot be middleware here: the code grant has no session
   * by definition, and a cross-origin caller has no cookie to send.
   */
  routes.post('/token', async (c) => {
    // Sets the header when the origin is registered; a same-origin request has
    // no Origin header and needs none.
    await allowOrigin(c)
    const body: unknown = await c.req.json().catch(() => null)

    const codeGrant = codeGrantSchema.safeParse(body)
    if (codeGrant.success) return exchangeAuthorizationCode(c, codeGrant.data)

    const serviceGrant = serviceGrantSchema.safeParse(body)
    if (serviceGrant.success) return exchangeClientCredentials(c, serviceGrant.data)

    const refreshGrant = refreshGrantSchema.safeParse(body)
    if (refreshGrant.success) return exchangeRefreshToken(c, refreshGrant.data)

    // Not any of the explicit grants. If it *looked* like one, say so rather
    // than falling through to a confusing "no session cookie" — a client with a
    // malformed grant request has a cookie problem only by coincidence.
    //
    // The issues reported are the ones for the grant it named, not the code
    // grant's: telling somebody who sent `refresh_token` that their `code` is
    // missing is a worse error than no error.
    if (typeof body === 'object' && body !== null && 'grantType' in body) {
      const named = (body as { grantType?: unknown }).grantType
      const failure =
        named === 'refresh_token'
          ? refreshGrant.error
          : named === 'client_credentials'
            ? serviceGrant.error
            : codeGrant.error
      throw badRequest(`Invalid ${typeof named === 'string' ? named : 'grant'} request`, {
        issues: failure.issues.map((issue) => ({
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

    /**
     * A refresh token, so the access token above can be short again (PEEK-108).
     *
     * Absent when the code carried no session — a code written before that
     * column existed, which expires within a minute of the deploy. The app then
     * gets exactly the old behaviour rather than an error, which is what makes
     * this deployable without coordinating the two halves.
     */
    const refresh = redemption.sessionId
      ? await issueRefreshToken({
          clientId: app.clientId,
          userId: redemption.userId,
          sessionId: redemption.sessionId,
        })
      : null

    await recordAudit({
      actorType: 'app',
      actorUserId: redemption.userId,
      actorClientId: app.clientId,
      action: 'token.exchange',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { expiresIn: issued.expiresIn, refresh: refresh !== null },
      requestId: c.get('requestId'),
    })

    return c.json(tokenResponse(issued, refresh?.refreshToken))
  }

  /**
   * `grant_type=refresh_token` — keeping a session alive without a redirect.
   *
   * Before this, an access token expiring cost a browser app a top-level
   * navigation and everything on screen, because there was nothing to exchange.
   * The mitigation was an hour-long access token; this is what lets that go
   * back down.
   *
   * **Every refusal is `invalid_grant`, and the reason goes to the audit log**
   * — same posture as the code grant, for the same reason. But one of them is
   * not routine: `reused` means two parties presented the same token, and
   * `redeemRefreshToken` has already revoked the entire chain by the time this
   * runs. It is recorded as `error` rather than `refused` so it is greppable as
   * the security event it is.
   */
  async function exchangeRefreshToken(
    c: Context<AppEnv>,
    input: z.infer<typeof refreshGrantSchema>,
  ) {
    const redemption = await redeemRefreshToken({
      refreshToken: input.refreshToken,
      clientId: input.clientId,
    })

    if (!redemption.ok) {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: input.clientId,
        action: 'token.refresh',
        outcome: redemption.reason === 'reused' ? 'error' : 'refused',
        detail: { reason: redemption.reason },
        requestId: c.get('requestId'),
      })
      throw badRequest('invalid_grant')
    }

    // Re-checked on every refresh, not just at sign-in. A refresh grant that
    // skipped this would let a disabled app or an offboarded person keep
    // minting tokens for as long as the session lasts, which is exactly the
    // hole a long-lived credential is expected to close rather than open.
    const app = await findAppPolicy(input.clientId)
    if (!app || app.status !== 'active') throw forbidden('Unknown or disabled app')

    const user = await findUserById(redemption.userId)
    if (!user || user.status !== 'active') {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: input.clientId,
        action: 'token.refresh',
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
      action: 'token.refresh',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { expiresIn: issued.expiresIn },
      requestId: c.get('requestId'),
    })

    return c.json(tokenResponse(issued, redemption.refreshToken))
  }

  /**
   * `grant_type=client_credentials` — how a bot signs (PEEK-34).
   *
   * The app authenticates as itself and receives a token for the role identity
   * it is registered to act as. There is no person anywhere in this flow, which
   * is the point: a role has nobody to sign in, and before this it could hold a
   * key it could never use.
   *
   * **The secret buys a ten-minute token, it is not one.** That keeps the same
   * TTL every other grant has, so offboarding a bot takes effect just as fast as
   * offboarding a person, and nothing long-lived travels on a signing request.
   *
   * Refusals are deliberately indistinguishable to the caller — unknown client,
   * wrong secret, public client, offboarded identity all answer the same. Which
   * one it was matters to us and is in the audit log; telling the caller turns
   * this endpoint into an oracle for enumerating credentials.
   */
  async function exchangeClientCredentials(
    c: Context<AppEnv>,
    input: z.infer<typeof serviceGrantSchema>,
  ) {
    const credential = await authenticateServiceCredential(input.clientId, input.clientSecret)
    if (!credential) {
      await recordAudit({
        actorType: 'app',
        actorClientId: input.clientId,
        action: 'token.issue',
        outcome: 'refused',
        detail: { reason: 'invalid_client', grant: 'client_credentials' },
        requestId: c.get('requestId'),
      })
      throw unauthenticated('invalid_client')
    }

    if (!credential.pubkey) throw forbidden('No active key for this identity')

    const issued = await issueToken({ pubkey: credential.pubkey, clientId: credential.clientId })

    await recordAudit({
      actorType: 'app',
      // The identity acted for, not a person who acted — there is none. Recording
      // it is what lets the audit trail answer "what has this bot been doing".
      actorUserId: credential.actsAsUserId,
      actorClientId: credential.clientId,
      action: 'token.issue',
      outcome: 'success',
      subjectPubkey: credential.pubkey,
      detail: { expiresIn: issued.expiresIn, grant: 'client_credentials' },
      requestId: c.get('requestId'),
    })

    return c.json(tokenResponse(issued))
  }

  return routes
}
