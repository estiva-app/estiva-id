/**
 * Require an admin, not merely a session.
 *
 * This began inside the invite route, where it was the only thing that needed
 * it and a middleware would have implied a policy that did not exist. The people
 * list (PEEK-64) is the second, so it moves here — two callers is the point at
 * which a copy starts drifting.
 *
 * Still deliberately thin. Roles are `admin` and `member` and nothing else;
 * PEEK-34 is where they become a real system, and this is the seam it will
 * extend rather than a permission model to be worked around in the meantime.
 */
import type { MiddlewareHandler } from 'hono'
import { findUserById } from '../../domain/users.js'
import { forbidden } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { requireRecentTap } from './recent-tap.js'
import { requireSession } from './session.js'

/**
 * Status is checked before role, and both are checked.
 *
 * A suspended admin is representable on purpose — status says whether somebody
 * may act at all, role says what they may do while active — so an offboarded
 * admin whose session has not yet expired must not still be able to read the
 * directory or mint invites.
 */
export const requireAdmin: MiddlewareHandler<AppEnv> = async (c, next) => {
  const { userId } = c.get('session')

  const user = await findUserById(userId)
  if (!user || user.status !== 'active') throw forbidden('That identity is no longer active')
  if (user.role !== 'admin') throw forbidden('That action needs an admin')

  await next()
}

/**
 * `requireSession` then `requireAdmin`, in that order.
 *
 * Ordering matters for the answer a caller gets: a stranger should be told they
 * are not signed in (`401`), not that they are not an admin (`403`), which would
 * confirm the route exists to somebody with no session at all.
 */
export const adminOnly = [requireSession, requireAdmin] as const

/**
 * An admin action that hands out access or a secret: an invite, a recovery
 * link, a role, an agent identity or its credential, an agent's signing kinds.
 * Past 15 minutes from the tap these ask for the passkey first (AUT-2; Miky,
 * 2026-10-16). Offboarding, reinstating, admitting and renaming do not.
 */
export const adminGrant = [...adminOnly, requireRecentTap] as const
