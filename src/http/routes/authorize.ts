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
    const { client_id, redirect_uri, code_challenge, state } = parsed.data

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
     */
    if (!session) {
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
    })

    await recordAudit({
      actorType: 'user',
      actorUserId: session.userId,
      actorClientId: client_id,
      action: 'authorize.issue',
      outcome: 'success',
      detail: { redirectUri: redirect_uri },
      requestId: c.get('requestId'),
    })

    const target = new URL(redirect_uri)
    target.searchParams.set('code', code)
    if (state) target.searchParams.set('state', state)
    return c.redirect(target.toString(), 302)
  })

  return routes
}
