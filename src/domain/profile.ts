/**
 * The public profile, and publishing it (PEEK-31).
 *
 * **This module is the reason one human stops looking like two.** Peek and Ship
 * each published their own kind:0 from their own users table, so the same
 * person arrived in each app with whatever name that app happened to hold. One
 * writer and two readers is the structural fix; the apps' publishers are being
 * removed, and `/sign` refuses kind:0 for every app precisely so they cannot
 * come back.
 *
 * Which is why publishing here does **not** go through `/sign`. That endpoint's
 * refusal is unconditional and should stay that way — an internal path using
 * {@link withUserSecretKey} is not a loophole in it, it is the one caller the
 * refusal exists to leave room for.
 */
import { config } from '../config.js'
import { query, queryOne, withTransaction } from '../db/pool.js'
import { logger } from '../logger.js'
import { type ProfileFields, buildProfile } from '../nostr/event.js'
import { signEvent } from '../nostr/keys.js'
import { publishEvent, relayBridgeUrl } from '../nostr/relay.js'
import { recordAudit } from './audit.js'
import { withUserSecretKey } from './keys.js'

/** NIP-05 restricts the local part; the relay resolves `?name=` case-insensitively. */
const HANDLE_PATTERN = /^[a-z0-9\-_.]+$/

export interface Profile {
  displayName: string | null
  picture: string | null
  /** Local part only — `jan`, not `jan@estiva.estiva.app`. */
  handle: string | null
  /** The host the handle is valid at, and what `nip05` is assembled from. */
  communityHost: string | null
}

export interface ProfileUpdate {
  displayName?: string | null
  picture?: string | null
  handle?: string | null
}

/**
 * The full `nip05` value as published: `<handle>@<community host>`.
 *
 * Assembled at publish time rather than stored, because the two halves have
 * different owners — the person picks the local part, the deployment decides
 * the host. Storing the joined string means a host change silently leaves every
 * row claiming the old domain, and Buzz *discards* a kind:0 whose handle domain
 * does not equal `communities.host` rather than erroring, so nobody would find
 * out (PEEK-59).
 */
export function nip05Value(profile: Profile): string | undefined {
  if (!profile.handle || !profile.communityHost) return undefined
  return `${profile.handle}@${profile.communityHost}`
}

export async function getProfile(userId: string): Promise<Profile | undefined> {
  const row = await queryOne<{
    display_name: string | null
    picture: string | null
    handle: string | null
    community_host: string | null
  }>(
    `select u.display_name, u.picture, h.handle, h.community_host
       from users u
       left join user_handles h
         on h.user_id = u.id and h.community_host = $2
      where u.id = $1`,
    [userId, config().COMMUNITY_HOST],
  )
  if (!row) return undefined
  return {
    displayName: row.display_name,
    picture: row.picture,
    handle: row.handle,
    communityHost: row.community_host,
  }
}

export class HandleTakenError extends Error {
  constructor(readonly handle: string) {
    super(`Handle ${handle} is already taken`)
    this.name = 'HandleTakenError'
  }
}

export class InvalidHandleError extends Error {
  constructor(readonly handle: string) {
    super(`Handle ${handle} is not a valid nip05 local part`)
    this.name = 'InvalidHandleError'
  }
}

/**
 * Write the profile.
 *
 * Fields absent from `update` are left alone; fields explicitly `null` are
 * cleared. That distinction is the whole reason this takes a partial rather
 * than a whole profile — "did not mention the handle" and "wants no handle" are
 * different intents, and collapsing them means an avatar change silently
 * revokes someone's nip05.
 */
export async function saveProfile(userId: string, update: ProfileUpdate): Promise<Profile> {
  const communityHost = config().COMMUNITY_HOST

  if (update.handle !== undefined && update.handle !== null) {
    const handle = update.handle.trim().toLowerCase()
    if (!HANDLE_PATTERN.test(handle)) throw new InvalidHandleError(update.handle)
    if (!communityHost) {
      throw new Error('COMMUNITY_HOST is not set; a handle cannot be assigned to a workspace')
    }
  }

  await withTransaction(async (client) => {
    if (update.displayName !== undefined) {
      await client.query('update users set display_name = $2, updated_at = now() where id = $1', [
        userId,
        update.displayName,
      ])
    }
    if (update.picture !== undefined) {
      await client.query('update users set picture = $2, updated_at = now() where id = $1', [
        userId,
        update.picture,
      ])
    }

    if (update.handle === null) {
      await client.query('delete from user_handles where user_id = $1 and community_host = $2', [
        userId,
        communityHost,
      ])
    } else if (update.handle !== undefined) {
      const handle = update.handle.trim().toLowerCase()
      try {
        await client.query(
          `insert into user_handles (user_id, community_host, handle) values ($1, $2, $3)
           on conflict (user_id, community_host)
           do update set handle = excluded.handle, updated_at = now()`,
          [userId, communityHost, handle],
        )
      } catch (error) {
        // 23505 is unique_violation. Reaching here means the *other* constraint
        // tripped — (community_host, handle) — i.e. somebody else holds it.
        if ((error as { code?: string }).code === '23505') throw new HandleTakenError(handle)
        throw error
      }
    }
  })

  const saved = await getProfile(userId)
  if (!saved) throw new Error(`No such user ${userId}`)
  return saved
}

export interface PublishOutcome {
  published: boolean
  eventId?: string
  /** Why nothing was published, when `published` is false. */
  reason?: string
}

/**
 * Sign and publish this person's kind:0.
 *
 * Failing to publish does **not** fail the save. The profile is stored here and
 * the relay is a projection of it, so a relay outage should leave the edit
 * standing and the projection stale — not lose the edit. The caller reports the
 * outcome so a stale projection is visible rather than silent.
 */
export async function publishProfile(
  userId: string,
  options: { requestId?: string } = {},
): Promise<PublishOutcome> {
  if (!relayBridgeUrl()) return { published: false, reason: 'relay_not_configured' }

  const profile = await getProfile(userId)
  if (!profile) return { published: false, reason: 'no_such_user' }

  const fields: ProfileFields = {
    display_name: profile.displayName ?? undefined,
    // Both spellings, because consumers read either one — see buildProfile.
    name: profile.displayName ?? undefined,
    picture: profile.picture ?? undefined,
    nip05: nip05Value(profile),
  }

  try {
    const result = await withUserSecretKey(userId, async (secretKey, pubkey) => {
      const event = signEvent(
        buildProfile(pubkey, Math.floor(Date.now() / 1000), fields),
        secretKey,
      )
      return { pubkey, ...(await publishEvent(event, secretKey)) }
    })

    await recordAudit({
      actorType: 'system',
      actorUserId: userId,
      action: 'profile.publish',
      outcome: result.ok ? 'success' : 'error',
      subjectPubkey: result.pubkey,
      detail: {
        eventId: result.eventId,
        duplicate: result.duplicate,
        // The handle is an org attestation, not private content, and whether it
        // reached the relay is the load-bearing fact during offboarding.
        nip05: fields.nip05 ?? null,
        ...(result.ok ? {} : { reason: result.reason, httpStatus: result.httpStatus }),
      },
      requestId: options.requestId,
    })

    if (!result.ok) {
      logger.warn({ userId, reason: result.reason }, 'profile publish rejected')
      return { published: false, reason: result.reason ?? 'rejected' }
    }
    return { published: true, eventId: result.eventId }
  } catch (error) {
    logger.error({ err: error, userId }, 'profile publish failed')
    await recordAudit({
      actorType: 'system',
      actorUserId: userId,
      action: 'profile.publish',
      outcome: 'error',
      detail: { reason: 'exception' },
      requestId: options.requestId,
    })
    return { published: false, reason: 'publish_failed' }
  }
}

/**
 * Republish every profile that claims a handle at the current community host.
 *
 * Exists because a handle only means anything while the relay holds the kind:0
 * that carries it: a relay that loses its events, or a community host that
 * changes, leaves everyone's attestation stale with nothing to notice. Not
 * wired to a route — an operator entry point, the same way the migration script
 * is.
 */
export async function republishAllProfiles(): Promise<{ published: number; failed: number }> {
  const rows = await query<{ user_id: string }>(
    `select u.id as user_id
       from users u
       join user_handles h on h.user_id = u.id
      where h.community_host = $1 and u.status = 'active'`,
    [config().COMMUNITY_HOST],
  )

  let published = 0
  let failed = 0
  for (const row of rows.rows) {
    const outcome = await publishProfile(row.user_id)
    if (outcome.published) published += 1
    else failed += 1
  }
  return { published, failed }
}
