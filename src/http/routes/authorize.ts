/**
 * `GET /authorize` — the browser half of the code flow (PEEK-90).
 *
 * An app on another origin sends a person here, they authenticate on *this*
 * origin, and they go back carrying a code the app exchanges for a token. The
 * session cookie never leaves this host, no CORS is opened, and the app never
 * sees a key.
 *
 * ## Two classes of failure, deliberately handled differently
 *
 * **Before the redirect URI is trusted, nothing is redirected.** An unknown
 * `client_id` or an unregistered `redirect_uri` renders an error here. Bouncing
 * to an unvalidated URI is how an identity provider becomes an open redirector,
 * and the payload would be an authorization code.
 *
 * **After it is trusted, failures go back to the app** as `?error=…`, which is
 * what OAuth clients are built to read. A person who denied consent and a
 * person whose account is suspended should both land back in the app, not on a
 * dead end here.
 *
 * ## No consent screen
 *
 * Every app is first-party — they are the suite. A prompt asking whether Estiva
 * Peek may act as you, inside Estiva, would be theatre. This changes the moment
 * a third-party app is registered, and that is the trigger to revisit it rather
 * than a general rule.
 *
 * ## `prompt=none` — the session probe an app shell boots on (PEEK-117)
 *
 * An app cannot ask this service whether a browser has a session any other way.
 * The cookie is `SameSite=Lax` and no CORS is served, so a `fetch` and a hidden
 * iframe are both blocked by design — a top-level navigation is the only thing
 * that carries the cookie, and that is not an accident to work around.
 *
 * So the probe *is* the redirect, and `prompt=none` only changes what happens
 * when it finds nothing: instead of parking the person on this origin's sign-in
 * page, it sends them back to the app with `error=login_required`. That single
 * difference is what lets an app own its own bootstrap — the shell asks, gets a
 * definite answer, and decides what to render. Without it every cold load with
 * no session ends on a screen belonging to a different product.
 */
import { Hono } from 'hono'
import { getCookie } from 'hono/cookie'
import { z } from 'zod'
import { findAppPolicy } from '../../domain/apps.js'
import { recordAudit } from '../../domain/audit.js'
import {
  CODE_CHALLENGE_METHOD,
  isRegisteredRedirectUri,
  issueAuthorizationCode,
} from '../../domain/authorization.js'
import { SESSION_COOKIE, resolveSession } from '../../domain/sessions.js'
import { findUserById } from '../../domain/users.js'
import { badRequest } from '../../errors.js'
import type { AppEnv } from '../app.js'

/**
 * `code_challenge` is base64url of a SHA-256, so 43 characters with no padding.
 * Pinning the shape here means a client that forgot to hash — sending the raw
 * verifier — is refused rather than silently getting a flow that only it can
 * complete, which would look like PKCE working.
 */
const requestSchema = z.object({
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  response_type: z.literal('code'),
  code_challenge: z.string().regex(/^[A-Za-z0-9\-_]{43}$/, 'must be base64url of a SHA-256'),
  code_challenge_method: z.literal(CODE_CHALLENGE_METHOD),
  state: z.string().min(1).max(512).optional(),
  scope: z.string().optional(),
  /**
   * `none` is the only value. Anything else is refused rather than ignored: a
   * client asking for `login` or `consent` is asking for behaviour this service
   * does not have, and silently giving it the default would look like it worked.
   */
  prompt: z.literal('none').optional(),
})

/** Send the person back to the app with an OAuth error, preserving `state`. */
function redirectWithError(
  redirectUri: string,
  error: string,
  state: string | undefined,
  description?: string,
): URL {
  const target = new URL(redirectUri)
  target.searchParams.set('error', error)
  if (description) target.searchParams.set('error_description', description)
  if (state) target.searchParams.set('state', state)
  return target
}

export function authorizeRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.get('/authorize', async (c) => {
    const parsed = requestSchema.safeParse(c.req.query())

    // Nothing is trusted yet, so nothing is redirected. `code_challenge_method`
    // failing here is how `plain` is refused: the literal accepts only S256,
    // and PKCE without hashing protects nothing an interceptor cannot replay.
    if (!parsed.success) {
      throw badRequest('Invalid authorization request', {
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      })
    }
    const { client_id, redirect_uri, code_challenge, state, prompt } = parsed.data

    const app = await findAppPolicy(client_id)
    if (!app || app.status !== 'active') {
      throw badRequest('Unknown or disabled app', { clientId: client_id })
    }
    if (!(await isRegisteredRedirectUri(client_id, redirect_uri))) {
      // Exact match, and deliberately not a helpful error: telling a caller
      // which URIs *are* registered enumerates them.
      throw badRequest('That redirect_uri is not registered for this app')
    }

    // --- From here the redirect URI is trusted -------------------------------

    const token = getCookie(c, SESSION_COOKIE)
    const session = token ? await resolveSession(token) : undefined

    /**
     * No session: sign in first, then come back.
     *
     * The app shell reads `next` and replays this request once authenticated
     * (PEEK-68). Until those screens exist this dead-ends at "You are not
     * signed in" — the contract is right and the screen is missing, rather than
     * the other way round.
     *
     * Only the path and query are carried, never an absolute URL: `next` is
     * attacker-influenced and an open redirect here would defeat the
     * allowlisting above.
     *
     * Unless the caller asked not to be prompted, in which case the honest
     * answer goes back to the app instead. `login_required` is the OIDC
     * spelling and it is a *successful probe with a negative result*, not an
     * error in the request — the shell that sent it is expecting exactly this
     * and will offer the passkey in place.
     */
    if (!session) {
      if (prompt === 'none') {
        // The app is the actor: there is no user to name, which is the result
        // being recorded. `refused` rather than `error` — nothing went wrong.
        await recordAudit({
          actorType: 'app',
          actorClientId: client_id,
          action: 'authorize.probe',
          outcome: 'refused',
          detail: { reason: 'login_required' },
          requestId: c.get('requestId'),
        })
        return c.redirect(redirectWithError(redirect_uri, 'login_required', state).toString(), 302)
      }
      const next = `${c.req.path}?${new URL(c.req.url).searchParams.toString()}`
      return c.redirect(`/?next=${encodeURIComponent(next)}`, 302)
    }

    const user = await findUserById(session.userId)
    if (!user || user.status !== 'active') {
      await recordAudit({
        actorType: 'user',
        actorUserId: session.userId,
        actorClientId: client_id,
        action: 'authorize.issue',
        outcome: 'refused',
        detail: { reason: user ? `user_${user.status}` : 'user_missing' },
        requestId: c.get('requestId'),
      })
      return c.redirect(
        redirectWithError(
          redirect_uri,
          'access_denied',
          state,
          'identity is not active',
        ).toString(),
        302,
      )
    }

    const { code } = await issueAuthorizationCode({
      clientId: client_id,
      userId: session.userId,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      sessionId: session.id,
    })

    /**
     * `silent` is what makes the auth-shell rates readable (PEEK-120).
     *
     * A code issued to a silent probe is somebody entering an app without
     * touching anything; a code issued without one is somebody who was asked
     * for a passkey. Recording only that a code was issued collapses the two,
     * and "how often does entry actually cost a person nothing" is the whole
     * question this milestone is judged on. With `actor_client_id` already on
     * the row, Peek and Ship are comparable rather than two unrelated systems.
     */
    await recordAudit({
      actorType: 'user',
      actorUserId: session.userId,
      actorClientId: client_id,
      action: 'authorize.issue',
      outcome: 'success',
      detail: {
        redirectUri: redirect_uri,
        silent: prompt === 'none',
        // A bot signing in to an app as this person (PER-22). The token minted
        // from this code will name it too; see `exchangeAuthorizationCode`.
        ...(session.delegate ? { delegate: session.delegate.clientId } : {}),
      },
      requestId: c.get('requestId'),
    })

    const target = new URL(redirect_uri)
    target.searchParams.set('code', code)
    if (state) target.searchParams.set('state', state)
    return c.redirect(target.toString(), 302)
  })

  return routes
}
