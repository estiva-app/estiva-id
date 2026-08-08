/**
 * The profile surface (PEEK-31).
 *
 * `GET /me/profile` and `PUT /me/profile` — read and edit the one profile that
 * gets published. Session-authed, because this is the person editing their own
 * identity on this origin; apps do not get a way in here at all, which is the
 * point of `/sign` refusing kind:0 unconditionally.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { getActivePubkey } from '../../domain/keys.js'
import {
  HandleTakenError,
  InvalidHandleError,
  getProfile,
  nip05Value,
  publishProfile,
  saveProfile,
} from '../../domain/profile.js'
import { findUserById } from '../../domain/users.js'
import { badRequest, conflict, forbidden, notFound } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { requireSession } from '../middleware/session.js'

/**
 * `null` clears a field, an absent key leaves it alone. `.optional().nullable()`
 * is what preserves that distinction through parsing — collapsing them would
 * make an avatar edit silently revoke a handle.
 */
const updateSchema = z
  .object({
    displayName: z.string().trim().max(200).nullable().optional(),
    picture: z.string().url().max(2048).nullable().optional(),
    handle: z.string().trim().min(1).max(64).nullable().optional(),
  })
  .strict()

function present(profile: Awaited<ReturnType<typeof getProfile>>, pubkey: string | undefined) {
  if (!profile) return undefined
  return {
    displayName: profile.displayName,
    picture: profile.picture,
    handle: profile.handle,
    communityHost: profile.communityHost ?? (config().COMMUNITY_HOST || null),
    nip05: nip05Value(profile) ?? null,
    pubkey: pubkey ?? null,
  }
}

export function profileRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.get('/me/profile', requireSession, async (c) => {
    const { userId } = c.get('session')
    const profile = await getProfile(userId)
    if (!profile) throw notFound('No such identity')
    return c.json(present(profile, await getActivePubkey(userId)))
  })

  routes.put('/me/profile', requireSession, async (c) => {
    const { userId } = c.get('session')

    const parsed = updateSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) {
      throw badRequest('Invalid profile', {
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      })
    }

    // A suspended or offboarded person must not be able to republish their own
    // handle. Offboarding revokes the attestation by publishing a kind:0
    // without it; letting them write here would hand it straight back.
    const user = await findUserById(userId)
    if (!user) throw notFound('No such identity')
    if (user.status !== 'active') throw forbidden('That identity is no longer active')

    let saved: Awaited<ReturnType<typeof saveProfile>>
    try {
      saved = await saveProfile(userId, parsed.data)
    } catch (error) {
      if (error instanceof HandleTakenError) {
        throw conflict('That handle is taken', { handle: error.handle })
      }
      if (error instanceof InvalidHandleError) {
        throw badRequest('A handle may contain only a-z, 0-9, dot, dash and underscore', {
          handle: error.handle,
        })
      }
      throw error
    }

    // Publishing is reported, not enforced: the save already happened and a
    // relay outage must not undo it. `published: false` is how a stale
    // projection becomes visible instead of silent.
    const outcome = await publishProfile(userId, { requestId: c.get('requestId') })

    return c.json({
      profile: present(saved, await getActivePubkey(userId)),
      published: outcome.published,
      eventId: outcome.eventId ?? null,
      ...(outcome.published ? {} : { publishError: outcome.reason ?? null }),
    })
  })

  return routes
}
