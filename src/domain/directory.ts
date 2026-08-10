/**
 * Who is in this workspace (PEEK-64).
 *
 * Nothing answered this for a human before. Buzz's `admin-web` is a moderation
 * console — reports and feedback — with no member management, and the admission
 * API has no interface anywhere. So this is the first place the question "who is
 * in this workspace, and are they actually set up" gets an answer.
 *
 * ## Three dimensions, kept apart on purpose
 *
 * A person is not one status. Collapsing these is how a half-onboarded or, far
 * worse, a half-offboarded person becomes invisible:
 *
 * | Dimension | Owner | Says |
 * | --- | --- | --- |
 * | `status` | this service | whether they may act here at all |
 * | `enrolment` | this service | how far through setup they got |
 * | `admission` | the Buzz relay | whether the relay will take their events |
 *
 * `users.status` deliberately does not claim to represent relay admission
 * (OPEN-SEAMS), and `enrolment` is derived rather than stored because it is a
 * fact about other rows — whether a passkey exists — not a state anyone sets.
 *
 * The mismatch is the signal. Someone `offboarded` here who is still `admitted`
 * at the relay is a security problem; someone `active` here who was never
 * admitted just cannot publish yet. Both are only visible because the columns
 * sit next to each other.
 *
 * ## Why invites are in the same list
 *
 * "Everyone in the workspace" includes the person an admin added yesterday who
 * has not opened their link. Putting invites on a separate screen is how that
 * person is forgotten — and the relay running closed means somebody has to
 * remember them twice over.
 */
import { config } from '../config.js'
import { query, queryOne } from '../db/pool.js'
import { type AdmissionStatus, admissionPort } from './admission.js'
import type { User } from './users.js'

/**
 * How far through setup somebody is.
 *
 * `enrolling` is the state that costs support time: the invite was opened, a
 * user row and a custodied key exist, and then the browser prompt was dismissed.
 * They own a pubkey and cannot sign in. It looks like nothing from every other
 * angle, which is why it is named.
 */
export type Enrolment = 'invited' | 'enrolling' | 'enrolled'

export interface DirectoryEntry {
  /**
   * `invite` rows are not accounts yet — no key, no pubkey, nothing to open.
   * The id is the invite's, so the two id spaces never collide.
   */
  kind: 'user' | 'invite'
  id: string
  email: string | null
  displayName: string | null
  handle: string | null
  /** Assembled, not stored — the domain comes from the current community host. */
  nip05: string | null
  pubkey: string | null
  role: User['role']
  /** Null for an invite: an account that does not exist has no status. */
  status: User['status'] | null
  enrolment: Enrolment
  passkeyCount: number
  lastSeenAt: string | null
  createdAt: string
  /** Observed from the relay, and `unknown` until Buzz can be asked. */
  admission: AdmissionStatus
  /** Invites only. A link nobody used is worth chasing before it dies. */
  expiresAt: string | null
}

interface PersonRow {
  id: string
  email: string | null
  display_name: string | null
  status: User['status']
  role: User['role']
  handle: string | null
  pubkey: string | null
  passkey_count: string
  last_seen_at: Date | null
  created_at: Date
}

/**
 * Everyone with an account, and everyone invited who has not started one.
 *
 * Two queries rather than a `union`: the rows mean different things and share
 * only a shape, and a union would need half its columns cast to null on each
 * side — which reads as if the two halves were the same kind of thing.
 */
export async function listDirectory(): Promise<DirectoryEntry[]> {
  const communityHost = config().COMMUNITY_HOST

  const people = await query<PersonRow>(
    `select u.id,
            u.email,
            u.display_name,
            u.status,
            u.role,
            h.handle,
            k.pubkey,
            (select count(*)
               from webauthn_credentials c
              where c.user_id = u.id and c.revoked_at is null)::text as passkey_count,
            (select max(s.last_seen_at)
               from sessions s
              where s.user_id = u.id) as last_seen_at,
            u.created_at
       from users u
       left join user_handles h on h.user_id = u.id and h.community_host = $1
       left join user_keys k on k.user_id = u.id and k.status = 'active'
      order by u.created_at`,
    [communityHost],
  )

  // Only invites nobody has opened. Once the link is claimed there is a user row
  // for it, and listing both would show that person twice — as an outstanding
  // invite and as the half-enrolled account they actually are.
  const invites = await query<{
    id: string
    email: string
    display_name: string | null
    handle: string | null
    role: User['role']
    expires_at: Date
    created_at: Date
  }>(
    `select id, email, display_name, handle, role, expires_at, created_at
       from invites
      where consumed_at is null
        and claimed_user_id is null
        and expires_at > now()
      order by created_at`,
  )

  const pubkeys = people.rows.map((row) => row.pubkey).filter((key): key is string => key !== null)
  const admission = await admissionPort().getAdmissionStatuses(pubkeys)

  const entries: DirectoryEntry[] = people.rows.map((row) => ({
    kind: 'user',
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    handle: row.handle,
    nip05: row.handle && communityHost ? `${row.handle}@${communityHost}` : null,
    pubkey: row.pubkey,
    role: row.role,
    status: row.status,
    enrolment: Number(row.passkey_count) > 0 ? 'enrolled' : 'enrolling',
    passkeyCount: Number(row.passkey_count),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    admission: (row.pubkey ? admission.get(row.pubkey) : undefined) ?? 'unknown',
    expiresAt: null,
  }))

  for (const invite of invites.rows) {
    entries.push({
      kind: 'invite',
      id: invite.id,
      email: invite.email,
      displayName: invite.display_name,
      handle: invite.handle,
      // Not assembled: nothing is published for a handle that is only reserved,
      // and showing `ada@estiva.estiva.app` would imply it already resolves.
      nip05: null,
      pubkey: null,
      role: invite.role,
      status: null,
      enrolment: 'invited',
      passkeyCount: 0,
      lastSeenAt: null,
      createdAt: invite.created_at.toISOString(),
      admission: 'unknown',
      expiresAt: invite.expires_at.toISOString(),
    })
  }

  return entries
}

/**
 * One person, by user id.
 *
 * Invites are deliberately not addressable here. There is nothing to open — an
 * unopened invite has no key, no passkeys and no history, and everything known
 * about it is already on the list row.
 */
export async function getDirectoryEntry(userId: string): Promise<DirectoryEntry | undefined> {
  const communityHost = config().COMMUNITY_HOST

  const row = await queryOne<PersonRow>(
    `select u.id,
            u.email,
            u.display_name,
            u.status,
            u.role,
            h.handle,
            k.pubkey,
            (select count(*)
               from webauthn_credentials c
              where c.user_id = u.id and c.revoked_at is null)::text as passkey_count,
            (select max(s.last_seen_at)
               from sessions s
              where s.user_id = u.id) as last_seen_at,
            u.created_at
       from users u
       left join user_handles h on h.user_id = u.id and h.community_host = $2
       left join user_keys k on k.user_id = u.id and k.status = 'active'
      where u.id = $1`,
    [userId, communityHost],
  )
  if (!row) return undefined

  return {
    kind: 'user',
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    handle: row.handle,
    nip05: row.handle && communityHost ? `${row.handle}@${communityHost}` : null,
    pubkey: row.pubkey,
    role: row.role,
    status: row.status,
    enrolment: Number(row.passkey_count) > 0 ? 'enrolled' : 'enrolling',
    passkeyCount: Number(row.passkey_count),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    admission: row.pubkey ? await admissionPort().getAdmissionStatus(row.pubkey) : 'unknown',
    expiresAt: null,
  }
}
