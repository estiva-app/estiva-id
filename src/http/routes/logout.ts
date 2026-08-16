/**
 * `GET /logout` — RP-initiated end session (PEEK-122).
 *
 * `POST /auth/logout` already ends a session, and an app on another origin
 * cannot reach it: the cookie is `SameSite=Lax` and no CORS is served, so a
 * cross-origin `POST` carries no session and logs nobody out. That is the same
 * constraint that made `/authorize` a redirect (PEEK-90), and it has the same
 * answer — a top-level navigation, which is the only thing that carries the
 * cookie.
 *
 * ## Why this had to exist
 *
 * Before the auth shell, an app "signing out" by dropping its own token was
 * narrow but defensible: signing back in was silent, which is what single
 * sign-on means. Once entry became automatic that turned into a button that
 * visibly does nothing — clear the token, reload, and the shell's silent probe
 * puts you straight back in against the untouched cookie.
 *
 * So sign-out in an app now means sign out of Estiva ID, and therefore out of
 * every app. That is a real behaviour change and it was decided deliberately,
 * not inherited.
 *
 * ## What it does not do
 *
 * **It does not revoke access tokens that have already been issued.** They are
 * stateless JWTs living up to `JWT_TTL_SECONDS`, so an app tab that is already
 * open keeps working until its token expires. Ending that properly needs either
 * short access tokens with a refresh grant (PEEK-108) or a revocation check on
 * every call, and neither is in scope here. What this guarantees is narrower and
 * worth stating exactly: **no new entry succeeds**, and every app asks for a
 * passkey the next time it boots.
 *
 * ## CSRF
 *
 * A `GET` end-session endpoint can be triggered by a third party — an `<img>`
 * tag is enough — which force-logs-out the person. That is the accepted shape of
 * OIDC RP-initiated logout: the impact is annoyance rather than compromise,
 * nothing is disclosed, and the alternative (a form POST from the app's origin)
 * cannot carry the cookie here for the reasons above. It is a deliberate
 * trade-off rather than an oversight.
 */
import { Hono } from 'hono'
import { deleteCookie, getCookie } from 'hono/cookie'
import { z } from 'zod'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import { isRegisteredRedirectUri } from '../../domain/authorization.js'
import { SESSION_COOKIE, resolveSession, revokeSession } from '../../domain/sessions.js'
import { badRequest } from '../../errors.js'
import type { AppEnv } from '../app.js'

const requestSchema = z.object({
  client_id: z.string().min(1),
  post_logout_redirect_uri: z.string().url(),
  state: z.string().min(1).max(512).optional(),
})

export function logoutRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.get('/logout', async (c) => {
    const parsed = requestSchema.safeParse(c.req.query())
    if (!parsed.success) {
      throw badRequest('Invalid logout request', {
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      })
    }
    const { client_id, post_logout_redirect_uri, state } = parsed.data

    const app = await findAppPolicy(client_id)
    if (!app || app.status !== 'active') {
      throw badRequest('Unknown or disabled app', { clientId: client_id })
    }

    /**
     * The same allowlist `/authorize` uses, and for the same reason.
     *
     * An end-session endpoint that redirects wherever it is told is an open
     * redirector — one that anybody can reach without a session, since logging
     * out an anonymous browser succeeds. Validating before redirecting is what
     * stops that, so it happens here rather than after the revocation.
     */
    if (!(await isRegisteredRedirectUri(client_id, post_logout_redirect_uri))) {
      throw badRequest('That post_logout_redirect_uri is not registered for this app')
    }

    // --- From here the redirect URI is trusted -------------------------------

    /**
     * Logging out when already logged out is a success, not a `401`.
     *
     * The caller's intent is "make there be no session", and there being none
     * already satisfies it. Refusing would make a double-click an error page.
     */
    const token = getCookie(c, SESSION_COOKIE)
    const session = token ? await resolveSession(token) : undefined

    if (token) await revokeSession(token)
    deleteCookie(c, SESSION_COOKIE, { path: '/' })

    if (session) {
      await recordAudit({
        actorType: 'user',
        actorUserId: session.userId,
        actorClientId: client_id,
        action: 'session.revoke',
        outcome: 'success',
        detail: { via: 'end_session' },
        requestId: c.get('requestId'),
      })
    }

    const target = new URL(post_logout_redirect_uri)
    if (state) target.searchParams.set('state', state)
    return c.redirect(target.toString(), 302)
  })

  return routes
}
