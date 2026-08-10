/**
 * Users.
 *
 * Email is a *private* directory attribute: it is stored here, it is never
 * published to a relay, and it never appears in a kind:0 event. That split is
 * the point of having a private directory alongside the public profile.
 */
import { queryOne, withTransaction } from '../db/pool.js'
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
}

export interface UserWithPubkey extends User {
  pubkey: string
}

export async function findUserByEmail(email: string): Promise<User | undefined> {
  return queryOne<User>(
    'select id, email, display_name, status, role from users where lower(email) = lower($1)',
    [email],
  )
}

export async function findUserById(id: string): Promise<User | undefined> {
  return queryOne<User>('select id, email, display_name, status, role from users where id = $1', [
    id,
  ])
}

/**
 * Change a person's status, revoking every session as they leave.
 *
 * Both halves are needed and neither is sufficient. Without the status change,
 * `/sign` keeps signing. Without the session revocation, they simply obtain a
 * fresh token from `/token` — a session is all that endpoint requires — and
 * carry on. Offboarding that does only one of these looks like it worked.
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
  email: string
  displayName?: string | undefined
  role?: 'admin' | 'member'
}): Promise<UserWithPubkey> {
  return withTransaction(async (client) => {
    const inserted = await client.query<User>(
      `insert into users (email, display_name, role) values ($1, $2, $3)
       returning id, email, display_name, status, role`,
      [input.email, input.displayName ?? null, input.role ?? 'member'],
    )
    const user = inserted.rows[0]
    if (!user) throw new Error('user insert returned no row')

    const pubkey = await mintKeyForUser(client, user.id)
    return { ...user, pubkey }
  })
}
