import type { MiddlewareHandler } from 'hono'
import { getCookie } from 'hono/cookie'
import { SESSION_COOKIE, resolveSession } from '../../domain/sessions.js'
import { unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'

/**
 * Require a browser session on the identity origin.
 *
 * Guards the self-serve surface (your profile, your passkeys) and token
 * issuance. It does **not** guard `/sign` — apps present a JWT there, not a
 * cookie, because they are on other origins.
 */
export const requireSession: MiddlewareHandler<AppEnv> = async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE)
  if (!token) throw unauthenticated('No session cookie')

  const session = await resolveSession(token)
  if (!session) throw unauthenticated('Session expired or revoked')

  c.set('session', session)
  await next()
}
