/**
 * Users.
 *
 * Email is a *private* directory attribute: it is stored here, it is never
 * published to a relay, and it never appears in a kind:0 event. That split is
 * the point of having a private directory alongside the public profile.
 */
import { query, queryOne, withTransaction } from '../db/pool.js'
import { recordAudit } from './audit.js'
import { mintKeyForUser } from './keys.js'

export interface User {
  id: string
  email: string | null
  display_name: string | null
  status: 'active' | 'suspended' | 'offboarded'
  /**
   * What they may do while active — a different axis from `status`, which says
   * whether they may act at all. Conflating them makes "suspended admin"
   * unrepresentable (PEEK-65).
   */
  role: 'admin' | 'member'
  /**
   * What sort of principal this is — a third axis again (PEEK-34).
   *
   * `human` custody is a temporary trade Stage 4 unwinds; `role` custody is
   * correct forever, because there is no human to hold the key. Undifferentiated,
   * Stage 4 would have no way to tell which rows to migrate.
   */
  kind: 'human' | 'role'
}

export interface UserWithPubkey extends User {
  pubkey: string
}

/** Every column the `User` shape needs, in one place so the two reads agree. */
const USER_COLUMNS = 'id, email, display_name, status, role, kind'

export async function findUserByEmail(email: string): Promise<User | undefined> {
  return queryOne<User>(`select ${USER_COLUMNS} from users where lower(email) = lower($1)`, [email])
}

export async function findUserById(id: string): Promise<User | undefined> {
  return queryOne<User>(`select ${USER_COLUMNS} from users where id = $1`, [id])
}

/**
 * Change a person's status, revoking every session as they leave.
 *
 * Both halves are needed and neither is sufficient. Without the status change,
 * `/sign` keeps signing. Without the session revocation, they simply sign in
 * again on it, or renew with the refresh token it backs, and carry on. Offboarding that does only one of these looks like it worked.
 *
 * **The key is deliberately left active.** A leaver keeps their keypair; that
 * is inherent and not something a database write can undo. What is withdrawn is
 * this service's willingness to act for them, plus admission at the relay and
 * the `nip05` attestation. Revoking the key row instead would also make their
 * signed history unattributable, which is the opposite of what offboarding
 * should mean.
 *
 * Not exposed over HTTP yet — the admin surface is PEEK-66. This is the
 * behaviour that surface will call, defined and tested up front so it cannot be
 * half-implemented there.
 *
 * **Audited (PEEK-69), and this was the gap that mattered.** Every other
 * privileged path in the service wrote a record and this one did not — which
 * meant the single action the custody argument most depends on being visible
 * was the one action nobody could see afterwards. An admin restoring somebody's
 * access and an admin seizing their account are the same call with a different
 * `status`; only this row tells them apart.
 */
export async function setUserStatus(
  userId: string,
  status: User['status'],
  by: {
    /** Who did it. Absent for a script or a migration, recorded as `system`. */
    actorUserId?: string | undefined
    requestId?: string | undefined
  } = {},
): Promise<{ sessionsRevoked: number }> {
  // Read first: "what it changed from" is the half that makes the record
  // meaningful, and after the update it is gone.
  const before = await findUserById(userId)

  const result = await withTransaction(async (client) => {
    await client.query('update users set status = $2, updated_at = now() where id = $1', [
      userId,
      status,
    ])

    if (status === 'active') return { sessionsRevoked: 0 }

    const revoked = await client.query(
      'update sessions set revoked_at = now() where user_id = $1 and revoked_at is null',
      [userId],
    )

    /**
     * Refresh tokens die with the account, in the same transaction (PEEK-108).
     *
     * Redemption already re-checks both the session and the user's status, so
     * this is the third independent thing that would have to fail before an
     * offboarded person could renew. It is here anyway because a long-lived
     * credential outliving the account it belongs to is the failure worth
     * three checks, and because "offboarding revokes refresh" should be a
     * statement in the code rather than a property you derive from a join.
     */
    await client.query(
      'update refresh_tokens set revoked_at = now() where user_id = $1 and revoked_at is null',
      [userId],
    )

    return { sessionsRevoked: revoked.rowCount ?? 0 }
  })

  await recordAudit({
    // `system` when nothing named an actor, rather than attributing an
    // unattended script to whoever happens to be passed in next.
    actorType: by.actorUserId ? 'user' : 'system',
    actorUserId: by.actorUserId,
    action: 'user.status_change',
    outcome: 'success',
    // Who it was done *to*. The actor is the admin; this is the subject.
    subjectPubkey: await activePubkeyFor(userId),
    detail: {
      subjectUserId: userId,
      from: before?.status ?? null,
      to: status,
      sessionsRevoked: result.sessionsRevoked,
    },
    requestId: by.requestId,
  })

  return result
}

/**
 * Why a role change was refused, in terms an admin screen can act on.
 *
 * Separated from a bare error so the console can say which rule was hit. Every
 * one of these is a state the caller could not have known from the row they
 * clicked, which is exactly when a generic failure is most annoying.
 */
export class RoleChangeRefused extends Error {
  constructor(readonly reason: 'no_such_person' | 'not_a_human' | 'not_active') {
    super(
      {
        no_such_person: 'No such person',
        not_a_human: 'A role identity cannot be an admin',
        not_active: 'Only an active identity can change role',
      }[reason],
    )
    this.name = 'RoleChangeRefused'
  }
}

/**
 * Promote or demote somebody (PEEK-163).
 *
 * Admin was previously set once, at account creation, and never afterwards —
 * so a workspace whose only admin left had no path back that did not involve
 * `psql`. This is that path.
 *
 * ## What it refuses, and why each one is not obvious from a row
 *
 * **A role identity is never an admin.** `createRoleIdentity` defaults a bot to
 * `member` deliberately, to keep "is this a person" and "what may they do"
 * independent rather than accidentally correlated. Letting the console promote
 * one would quietly re-correlate them, and a bot with a workspace-admin role is
 * a capability nobody asked for and no passkey guards.
 *
 * **An inactive identity cannot change role.** Granting admin to somebody
 * offboarded creates a dormant privilege that reactivating silently restores —
 * the reinstate flow checks status, not what the account gained while away.
 *
 * ## What it does not police
 *
 * Whether the *caller* may do this at all, and whether they are editing their
 * own row. Both are the route's, because both are facts about the request
 * rather than about the target — see `admin.ts`.
 *
 * Idempotent: setting the role somebody already has writes nothing and records
 * nothing, because an audit trail full of no-ops is one nobody reads.
 */
export async function setUserRole(
  userId: string,
  role: User['role'],
  by: { actorUserId?: string | undefined; requestId?: string | undefined } = {},
): Promise<{ from: User['role']; to: User['role']; changed: boolean }> {
  const before = await findUserById(userId)
  if (!before) throw new RoleChangeRefused('no_such_person')
  if (before.kind !== 'human') throw new RoleChangeRefused('not_a_human')
  if (before.status !== 'active') throw new RoleChangeRefused('not_active')

  if (before.role === role) return { from: before.role, to: role, changed: false }

  await query('update users set role = $2, updated_at = now() where id = $1', [userId, role])

  await recordAudit({
    actorType: by.actorUserId ? 'user' : 'system',
    actorUserId: by.actorUserId,
    action: 'user.role_change',
    outcome: 'success',
    // The subject is who it was done to; the actor is the admin who did it.
    subjectPubkey: await activePubkeyFor(userId),
    detail: { subjectUserId: userId, from: before.role, to: role },
    requestId: by.requestId,
  })

  return { from: before.role, to: role, changed: true }
}

/** Offboard a person: they stop being able to act, but keep their history. */
export async function offboardUser(
  userId: string,
  by: { actorUserId?: string | undefined; requestId?: string | undefined } = {},
): Promise<{ sessionsRevoked: number }> {
  return setUserStatus(userId, 'offboarded', by)
}

/**
 * The pubkey to file a record against.
 *
 * Local rather than imported from `keys.ts`, which imports this module — and a
 * cycle between "who someone is" and "what they can sign with" is not worth
 * introducing for one column.
 */
async function activePubkeyFor(userId: string): Promise<string | undefined> {
  const row = await queryOne<{ pubkey: string }>(
    "select pubkey from user_keys where user_id = $1 and status = 'active'",
    [userId],
  )
  return row?.pubkey
}

/**
 * Create a user and mint their key in one transaction.
 *
 * A user without a key would be an account that cannot act, and a key without a
 * user would be an orphaned secret. Neither is a state worth being able to
 * represent, so both happen or neither does.
 */
export async function createUserWithKey(input: {
  /**
   * Optional, because a role identity need not have one (PEEK-34). A human
   * always does — it arrives from the invite, which is what makes an enrolment
   * link non-transferable.
   */
  email?: string | null
  displayName?: string | undefined
  role?: 'admin' | 'member'
  kind?: 'human' | 'role'
  /**
   * The human this identity belongs to, for a personal bot (PEEK-164).
   *
   * Null for a human and for a workspace-owned role. The column's own check
   * refuses it on a human; that an owner must itself be human is enforced in
   * `createRoleIdentity`, since it is a statement about another row.
   */
  ownerUserId?: string | null
  /** A QA persona that signs in with a secret instead of a passkey (PER-22). */
  testAccount?: boolean
}): Promise<UserWithPubkey> {
  return withTransaction(async (client) => {
    const inserted = await client.query<User>(
      `insert into users (email, display_name, role, kind, owner_user_id, test_account)
       values ($1, $2, $3, $4, $5, $6)
       returning ${USER_COLUMNS}`,
      [
        input.email ?? null,
        input.displayName ?? null,
        input.role ?? 'member',
        input.kind ?? 'human',
        input.ownerUserId ?? null,
        input.testAccount ?? false,
      ],
    )
    const user = inserted.rows[0]
    if (!user) throw new Error('user insert returned no row')

    const pubkey = await mintKeyForUser(client, user.id)
    return { ...user, pubkey }
  })
}
