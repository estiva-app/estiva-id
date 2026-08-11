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
 *
 * **It means "never had a passkey", not "has no passkey now."** Offboarding
 * revokes every credential (PEEK-66), so deriving this from the *live* count
 * labelled every leaver "never signed in" — which is false, and falsest exactly
 * where it matters: on the screen an admin checks after removing somebody.
 */
/**
 * `not-applicable` is for role identities (PEEK-34).
 *
 * A bot has no passkey and never will, so every human enrolment state is a lie
 * about it — and the most damaging is `enrolling`, which the derivation would
 * otherwise produce: it renders as "Never signed in" and counts towards "not
 * fully set up", telling an admin to chase somebody who does not exist. A role
 * is not part-way through setup; setup does not apply to it.
 */
export type Enrolment = 'invited' | 'enrolling' | 'enrolled' | 'not-applicable'

export interface DirectoryEntry {
  /**
   * `invite` rows are not accounts yet — no key, no pubkey, nothing to open.
   * The id is the invite's, so the two id spaces never collide.
   *
   * `role` is an account, with a key and a profile, and no way to sign in.
   * Distinguishing it here rather than by a flag is what stops every screen
   * having to remember to ask (PEEK-34).
   */
  kind: 'user' | 'invite' | 'role'
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

/**
 * The enrolment state for one account row.
 *
 * Split out because both reads derive it and they must agree — the list and the
 * detail view disagreeing about whether somebody is set up is the kind of bug
 * that gets argued about rather than noticed.
 */
function roleEnrolment(row: { kind: User['kind']; ever_enrolled: boolean }): Enrolment {
  if (row.kind === 'role') return 'not-applicable'
  return row.ever_enrolled ? 'enrolled' : 'enrolling'
}

interface PersonRow {
  id: string
  email: string | null
  display_name: string | null
  status: User['status']
  role: User['role']
  kind: User['kind']
  handle: string | null
  pubkey: string | null
  passkey_count: string
  ever_enrolled: boolean
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
            u.kind,
            h.handle,
            k.pubkey,
            (select count(*)
               from webauthn_credentials c
              where c.user_id = u.id and c.revoked_at is null)::text as passkey_count,
            -- Revoked ones included: this answers "did they ever enrol", which
            -- offboarding must not be able to rewrite.
            exists (select 1 from webauthn_credentials c where c.user_id = u.id) as ever_enrolled,
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
    kind: row.kind === 'role' ? 'role' : 'user',
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    handle: row.handle,
    nip05: row.handle && communityHost ? `${row.handle}@${communityHost}` : null,
    pubkey: row.pubkey,
    role: row.role,
    status: row.status,
    // A role has no passkey and never will, so the human ladder does not apply.
    // Deriving it would produce `enrolling`, which reads as "cannot get in and
    // does not know it" — an admin chasing a bot that is working perfectly.
    enrolment: roleEnrolment(row),
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
 * What one member may learn about another (PEEK-30).
 *
 * The private half of a person. Deliberately *not* what the admin list returns:
 * no passkey counts, no last-seen, no enrolment state, no admission — those
 * describe how somebody's account is doing, which is an admin's business and
 * nobody else's.
 *
 * `status` is here because an app that cannot tell a current colleague from a
 * former one will render a leaver as an ordinary member forever, and this
 * service's whole position on offboarding is that a mismatch should be visible
 * rather than silent. Their name and email still resolve, because their old
 * messages have to keep rendering as written by a person.
 */
export interface DirectoryContact {
  pubkey: string
  displayName: string | null
  /**
   * **Never published to a relay, and never in a `kind:0`.** A private contact
   * address on a shared relay is unretractable; Nostr's slot for a public
   * identifier is `nip05`. That split is the point of this endpoint existing
   * alongside the profile rather than inside it.
   */
  email: string | null
  role: User['role']
  status: User['status']
}

/**
 * Look people up by pubkey.
 *
 * **By pubkey, and only by pubkey — there is no way to list.** A caller has to
 * already know who it is asking about, which it does because it read the pubkey
 * off an event it could already see. That is what keeps a token scoped to one
 * app from being a way to export the staff directory.
 *
 * Batch, because the caller is an app rendering a thread with a dozen authors
 * and the round trip is cross-origin. A per-pubkey endpoint would make the
 * obvious implementation a dozen preflighted requests.
 *
 * Unknown pubkeys are simply absent from the result. There is nothing to say
 * about them, and an explicit "no such person" for every key an app has ever
 * seen would turn this into a way to test which keys are members.
 */
export async function lookupContacts(pubkeys: readonly string[]): Promise<DirectoryContact[]> {
  if (pubkeys.length === 0) return []

  const result = await query<{
    pubkey: string
    display_name: string | null
    email: string | null
    role: User['role']
    status: User['status']
  }>(
    `select k.pubkey, u.display_name, u.email, u.role, u.status
       from user_keys k
       join users u on u.id = k.user_id
      where k.status = 'active' and k.pubkey = any($1::text[])`,
    [pubkeys],
  )

  return result.rows.map((row) => ({
    pubkey: row.pubkey,
    displayName: row.display_name,
    email: row.email,
    role: row.role,
    status: row.status,
  }))
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
            u.kind,
            h.handle,
            k.pubkey,
            (select count(*)
               from webauthn_credentials c
              where c.user_id = u.id and c.revoked_at is null)::text as passkey_count,
            -- Revoked ones included: this answers "did they ever enrol", which
            -- offboarding must not be able to rewrite.
            exists (select 1 from webauthn_credentials c where c.user_id = u.id) as ever_enrolled,
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
    kind: row.kind === 'role' ? 'role' : 'user',
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    handle: row.handle,
    nip05: row.handle && communityHost ? `${row.handle}@${communityHost}` : null,
    pubkey: row.pubkey,
    role: row.role,
    status: row.status,
    // A role has no passkey and never will, so the human ladder does not apply.
    // Deriving it would produce `enrolling`, which reads as "cannot get in and
    // does not know it" — an admin chasing a bot that is working perfectly.
    enrolment: roleEnrolment(row),
    passkeyCount: Number(row.passkey_count),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    admission: row.pubkey ? await admissionPort().getAdmissionStatus(row.pubkey) : 'unknown',
    expiresAt: null,
  }
}
