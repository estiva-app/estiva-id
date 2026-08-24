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
import { recordAudit } from '../../domain/audit.js'
import { AvatarRejected, MAX_AVATAR_BYTES, setAvatar } from '../../domain/avatar.js'
import { getActivePubkey } from '../../domain/keys.js'
import {
  HandleTakenError,
  InvalidHandleError,
  getProfile,
  nip05Value,
  publishProfile,
  saveProfile,
} from '../../domain/profile.js'
import { admitMember } from '../../domain/relay-membership.js'
import {
  MAX_BOTS_PER_PERSON,
  RoleRefused,
  TooManyBots,
  botsOwnedBy,
  createOwnBot,
} from '../../domain/roles.js'
import { findUserById } from '../../domain/users.js'
import {
  AppError,
  badRequest,
  conflict,
  forbidden,
  notFound,
  policyViolation,
} from '../../errors.js'
import type { AppEnv } from '../app.js'
import { requireSession } from '../middleware/session.js'

/**
 * `null` clears a field, an absent key leaves it alone. `.optional().nullable()`
 * is what preserves that distinction through parsing — collapsing them would
 * make an avatar edit silently revoke a handle.
 */
const botSchema = z.object({ label: z.string().min(1).max(80) })

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

  /**
   * Make a bot for yourself (PEEK-164).
   *
   * **No admin.** That is the whole point: onboarding one more person to the
   * agent needed an admin for three separate steps, and PEEK-163 existed only
   * to make one of them possible. A person who can sign in can make their own.
   *
   * What stops this being an escalation is in `createOwnBot`: the credential is
   * NIP-98 only, so it can read and cannot publish; the display name is
   * composed rather than accepted, so it cannot claim to be somebody else; and
   * the bot is owned, so `offboardPerson` takes it when its owner goes.
   *
   * The secret is returned **once** and stored only as a hash, exactly like the
   * admin path — this route is a different door to the same room, not a
   * different room.
   */
  routes.post('/me/bots', requireSession, async (c) => {
    const { userId } = c.get('session')
    const parsed = botSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) throw badRequest('Expected { label }')

    let created: Awaited<ReturnType<typeof createOwnBot>>
    try {
      created = await createOwnBot({ ownerUserId: userId, label: parsed.data.label })
    } catch (error) {
      if (error instanceof TooManyBots) throw conflict(error.message, { reason: 'too_many_bots' })
      if (error instanceof RoleRefused) throw conflict(error.message, { reason: error.reason })
      throw error
    }

    /*
      Admitted here, the way enrolment admits a person's own key rather than
      leaving it for an admin — otherwise self-service would remove two steps of
      three and the bot would be born unable to read anything.
      `relay_membership_required` is what it would hit, which reads as a
      permission bug and is actually a missing member.

      **Failure does not fail creation**, mirroring enrolment for the same
      reason: the credential exists and works everywhere except the relay, and
      throwing here would destroy something the caller can never see again —
      the secret is returned once.
    */
    const admission = created.pubkey
      ? await admitMember(created.pubkey)
      : { ok: false, reason: 'no active key for this identity' }

    await recordAudit({
      actorType: 'user',
      actorUserId: userId,
      action: 'role.create',
      outcome: 'success',
      subjectPubkey: created.pubkey ?? undefined,
      detail: {
        subjectUserId: created.botUserId,
        displayName: created.displayName,
        clientId: created.clientId,
        selfService: true,
        admitted: admission.ok,
        ...(admission.ok ? {} : { admissionError: admission.reason }),
      },
      requestId: c.get('requestId'),
    })

    return c.json({
      bot: {
        userId: created.botUserId,
        displayName: created.displayName,
        pubkey: created.pubkey,
      },
      clientId: created.clientId,
      // Shown once. Only its hash is stored.
      clientSecret: created.secret,
      admitted: admission.ok,
      ...(admission.ok ? {} : { admissionError: admission.reason ?? null }),
    })
  })

  routes.get('/me/bots', requireSession, async (c) => {
    const { userId } = c.get('session')
    return c.json({ bots: await botsOwnedBy(userId), limit: MAX_BOTS_PER_PERSON })
  })

  /**
   * Upload a profile picture (PEEK-32).
   *
   * Raw bytes with a `Content-Type`, not multipart. There is exactly one file
   * and no other fields, so a multipart envelope would be parsing overhead
   * around a body we already have — and `fetch(file)` in the browser sends this
   * shape with no work at all.
   *
   * Separate from `PUT /me/profile` because it fails differently: that route
   * cannot fail at the relay in a way that loses the edit, and this one can be
   * refused outright by a media store that has never heard of the person.
   */
  routes.put('/me/avatar', requireSession, async (c) => {
    const { userId } = c.get('session')

    const user = await findUserById(userId)
    if (!user) throw notFound('No such identity')
    if (user.status !== 'active') throw forbidden('That identity is no longer active')

    const contentType = c.req.header('content-type') ?? ''
    const body = new Uint8Array(await c.req.arrayBuffer())

    try {
      const outcome = await setAvatar(userId, body, contentType, {
        requestId: c.get('requestId'),
      })
      return c.json({
        profile: present(await getProfile(userId), await getActivePubkey(userId)),
        avatar: { url: outcome.url, sha256: outcome.sha256, size: outcome.size },
        published: outcome.published,
        eventId: outcome.eventId ?? null,
        ...(outcome.published ? {} : { publishError: outcome.publishError ?? null }),
      })
    } catch (error) {
      if (error instanceof AvatarRejected) {
        throw badRequest(error.message, { reason: error.reason, maxBytes: MAX_AVATAR_BYTES })
      }
      // An upload the relay refused. `not_admitted` is called out on its own
      // because it is the one an operator can fix in a minute, and telling
      // somebody "upload failed" when the answer is "nobody has let you in yet"
      // sends them looking in the wrong place — see the closed-relay note in
      // deploy/README.md.
      if (isUploadFailure(error)) {
        if (error.reason === 'not_admitted') {
          throw forbidden('This identity has not been admitted to the relay yet', {
            reason: 'not_admitted',
          })
        }
        // `rejected` is the media store declining this content — wrong type,
        // too large, rate limited. Well-formed request, refused on policy,
        // which is what `policy_violation` already means here. `unreachable`
        // is ours and stays a 500.
        if (error.reason === 'rejected') {
          throw policyViolation('The media store refused that file', {
            reason: error.reason,
            detail: error.message,
          })
        }
        throw new AppError('internal', 'Could not reach the media store', {
          reason: error.reason,
        })
      }
      throw error
    }
  })

  return routes
}

function isUploadFailure(
  error: unknown,
): error is { ok: false; reason: string; message: string; httpStatus: number } {
  return typeof error === 'object' && error !== null && 'ok' in error && 'reason' in error
}
