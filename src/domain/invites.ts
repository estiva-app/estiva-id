/**
 * Invites (PEEK-65).
 *
 * The only way to create an identity. Registration used to be open, which was
 * survivable only because a caller had to know the API — and the registration
 * screen removes that, so the gate ships with it.
 *
 * An invite link is a bearer credential that will sit in somebody's chat
 * history, so it is treated like one: hashed at rest, time-boxed, single-use,
 * and carrying the fields the admin filled in so the invitee cannot quietly
 * become someone else.
 */
import { createHash, randomBytes } from 'node:crypto'
import { query, queryOne } from '../db/pool.js'

/**
 * How long a link stays usable.
 *
 * Seven days. Long enough to survive a weekend and a forgotten DM, short enough
 * that a link found in a chat log a year later is dead.
 */
export const INVITE_TTL_HOURS = 24 * 7

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

export type Role = 'admin' | 'member'

export interface Invite {
  id: string
  email: string
  displayName: string | null
  handle: string | null
  role: Role
  expiresAt: Date
  claimedUserId: string | null
}

export interface CreatedInvite extends Invite {
  /** Shown once, at creation. Never recoverable — only its hash is stored. */
  token: string
}

export async function createInvite(input: {
  email: string
  displayName?: string | undefined
  handle?: string | undefined
  role?: Role
  /** Null for the bootstrap invite, which no admin exists to attribute. */
  createdBy: string | null
  ttlHours?: number
}): Promise<CreatedInvite> {
  const token = randomBytes(32).toString('base64url')
  const expiresAt = new Date(Date.now() + (input.ttlHours ?? INVITE_TTL_HOURS) * 3600 * 1000)

  const row = await queryOne<{ id: string }>(
    `insert into invites (token_hash, email, display_name, handle, role, created_by, expires_at)
     values ($1, $2, $3, $4, $5, $6, $7)
     returning id`,
    [
      sha256(token),
      input.email,
      input.displayName ?? null,
      input.handle ?? null,
      input.role ?? 'member',
      input.createdBy,
      expiresAt,
    ],
  )
  if (!row) throw new Error('invite insert returned no row')

  return {
    id: row.id,
    token,
    email: input.email,
    displayName: input.displayName ?? null,
    handle: input.handle ?? null,
    role: input.role ?? 'member',
    expiresAt,
    claimedUserId: null,
  }
}

export type InviteRejection = 'unknown' | 'expired' | 'consumed'

export type InviteLookup = { ok: true; invite: Invite } | { ok: false; reason: InviteRejection }

/**
 * Resolve a token to the invite behind it.
 *
 * Read-only: nothing is consumed here, because this is called both by the
 * enrolment screen (to prefill a form somebody may abandon) and by the
 * registration route.
 */
export async function findInvite(token: string): Promise<InviteLookup> {
  const row = await queryOne<{
    id: string
    email: string
    display_name: string | null
    handle: string | null
    role: Role
    expires_at: Date
    claimed_user_id: string | null
    consumed: boolean
    expired: boolean
  }>(
    `select id, email, display_name, handle, role, expires_at, claimed_user_id,
            consumed_at is not null as consumed,
            expires_at <= now() as expired
       from invites where token_hash = $1`,
    [sha256(token)],
  )

  if (!row) return { ok: false, reason: 'unknown' }
  if (row.consumed) return { ok: false, reason: 'consumed' }
  if (row.expired) return { ok: false, reason: 'expired' }

  return {
    ok: true,
    invite: {
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      handle: row.handle,
      role: row.role,
      expiresAt: row.expires_at,
      claimedUserId: row.claimed_user_id,
    },
  }
}

/**
 * Bind the invite to the user row created for it.
 *
 * Called when enrolment *starts*. The pairing is what lets somebody who
 * cancelled the passkey prompt reopen the same link and land on the same
 * account, rather than stranding an unreachable user row and a dead invite.
 */
export async function claimInvite(inviteId: string, userId: string): Promise<void> {
  await query('update invites set claimed_user_id = $2 where id = $1', [inviteId, userId])
}

/**
 * Burn the invite for a user, once a passkey actually exists.
 *
 * Keyed by user rather than by token because the verify step only knows which
 * account the challenge belonged to — the token never reaches it. That is the
 * point of {@link claimInvite} binding the two at the start.
 *
 * Deliberately not done at claim time: the most common way enrolment fails is
 * somebody dismissing the browser prompt, and burning the link there would turn
 * a mis-click into a support request.
 */
export async function consumeInviteForUser(userId: string): Promise<Invite | undefined> {
  const row = await queryOne<{ id: string; handle: string | null; role: Role; email: string }>(
    `update invites set consumed_at = now()
      where claimed_user_id = $1 and consumed_at is null
      returning id, handle, role, email`,
    [userId],
  )
  if (!row) return undefined
  return {
    id: row.id,
    email: row.email,
    displayName: null,
    handle: row.handle,
    role: row.role,
    expiresAt: new Date(),
    claimedUserId: userId,
  }
}

/** Outstanding invites, for the people list (PEEK-64). Never returns tokens. */
export async function listPendingInvites(): Promise<Invite[]> {
  const result = await query<{
    id: string
    email: string
    display_name: string | null
    handle: string | null
    role: Role
    expires_at: Date
    claimed_user_id: string | null
  }>(
    `select id, email, display_name, handle, role, expires_at, claimed_user_id
       from invites
      where consumed_at is null and expires_at > now()
      order by created_at desc`,
  )
  return result.rows.map((row) => ({
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    handle: row.handle,
    role: row.role,
    expiresAt: row.expires_at,
    claimedUserId: row.claimed_user_id,
  }))
}

/** Whether anybody can invite yet — false on a fresh deployment. */
export async function anyAdminExists(): Promise<boolean> {
  const row = await queryOne<{ present: boolean }>(
    "select exists (select 1 from users where role = 'admin' and status = 'active') as present",
  )
  return row?.present === true
}
