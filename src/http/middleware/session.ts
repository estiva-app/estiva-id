import type { MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import { recordAudit } from '../../domain/audit.js'
import { SESSION_COOKIE, resolveSession } from '../../domain/sessions.js'
import { forbidden, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'

/**
 * Require a browser session on the identity origin.
 *
 * Guards the self-serve surface (your profile, your passkeys) and token
 * issuance. It does **not** guard `/sign` — apps present a JWT there, not a
 * cookie, because they are on other origins.
 *
 * ## Delegated sessions are refused here (PER-22)
 *
 * A session a person granted to their bot reaches app sign-in — `/authorize`,
 * which resolves the cookie itself — and nothing behind this guard. Refused by default rather than listed per route, so the next account
 * or admin route added is closed to a bot without anybody remembering to close
 * it. The few that are safe opt in with {@link requireAnySession}.
 */
export const requireSession: MiddlewareHandler<AppEnv> = sessionGuard({ allowDelegated: false })

/**
 * The same, but a delegated session passes too. For routes that only say who
 * the caller is or end their own session — nothing that changes the account.
 */
export const requireAnySession: MiddlewareHandler<AppEnv> = sessionGuard({ allowDelegated: true })

function sessionGuard({ allowDelegated }: { allowDelegated: boolean }): MiddlewareHandler<AppEnv> {
  return async (c, next) => {
    const token = getCookie(c, SESSION_COOKIE)
    if (!token) throw unauthenticated('No session cookie')

    const session = await resolveSession(token)
    if (!session) throw unauthenticated('Session expired or revoked')

    if (session.delegate && !allowDelegated) {
      // Audited because a bot reaching for the account or admin surface is the
      // one thing about a delegated session somebody would want to know.
      await recordAudit({
        actorType: 'app',
        actorUserId: session.userId,
        actorClientId: session.delegate.clientId,
        action: 'session.delegate_refused',
        outcome: 'refused',
        detail: { method: c.req.method, path: c.req.path },
        requestId: c.get('requestId'),
      })
      throw forbidden('A session granted to a bot cannot do that', { reason: 'delegated_session' })
    }

    c.set('session', session)
    await next()
  }
}
