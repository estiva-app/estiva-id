import type { MiddlewareHandler } from 'hono'
import { config } from '../../config.js'
import { forbidden } from '../../errors.js'
import type { AppEnv } from '../app.js'

/**
 * Require a passkey tap in the last {@link config}`().REAUTH_SECONDS` (AUT-2).
 *
 * A sign-in lasts up to 14 days, so the cookie alone says only that somebody
 * is at a laptop that was signed in. The changes that would let them keep the
 * account — a passkey of their own, removing yours, signing your other devices
 * out, and an admin's invite, recovery link, role change or agent secret — ask
 * for the passkey again once the last tap is older than that (Miky,
 * 2026-10-16). The page answers `reauth_required` with
 * `POST /auth/reauth/options` → `/auth/reauth/verify`, then retries.
 *
 * After `requireSession` (or `adminOnly`), which puts the session there.
 */
export const requireRecentTap: MiddlewareHandler<AppEnv> = async (c, next) => {
  const { authenticatedAt } = c.get('session')
  if (Date.now() - authenticatedAt.getTime() > config().REAUTH_SECONDS * 1000) {
    throw forbidden('Confirm it is you with your passkey first', { reason: 'reauth_required' })
  }
  await next()
}
