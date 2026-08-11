/**
 * Account recovery (PEEK-67).
 *
 * Somebody loses every device that held a passkey. Enrolling another one needs
 * an existing session, which is precisely what they cannot get — so without a
 * way in from outside, the account is simply gone. That is also why revoking
 * your last passkey is refused: the refusal only makes sense if this exists.
 *
 * **The pubkey does not change.** Nothing here touches `user_keys`, so every
 * event the person ever signed stays theirs. In consumer Nostr "lose your key,
 * lose your identity" is accepted; for an employer it is not, and this is the
 * thing custody actually buys.
 *
 * ## An admin doing this is indistinguishable from an admin taking the account
 *
 * Mechanically they are the same act: a new credential appears on somebody
 * else's identity at an admin's instruction. Only the trail separates them,
 * which is why issuing *and* redeeming are both audited and both surfaced to
 * the person on their own account page — not merely to other admins.
 */
import { createHash, randomBytes } from 'node:crypto'
import { query, queryOne } from '../db/pool.js'
import { findUserById } from './users.js'

/**
 * How long a recovery link lives.
 *
 * A day, against an invite's week. An invite opens a new, empty identity; this
 * opens an existing one with history and a custodied key behind it, and it is
 * issued in response to somebody actively asking. The window only has to cover
 * "the admin sends it and the person clicks it", so a week of exposure buys
 * nothing and costs a link sitting live in a chat log.
 */
export const RECOVERY_TTL_HOURS = 24

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

export interface RecoveryToken {
  id: string
  userId: string
  expiresAt: Date
}

export interface CreatedRecovery extends RecoveryToken {
  /** Shown once, at creation. Only its hash is stored. */
  token: string
}

export class RecoveryRefused extends Error {
  constructor(readonly reason: 'no_such_person' | 'not_active' | 'not_a_person') {
    super(
      {
        no_such_person: 'No such person',
        not_active: 'Only an active identity can be recovered',
        not_a_person: 'A role identity has no passkey to recover',
      }[reason],
    )
    this.name = 'RecoveryRefused'
  }
}

/**
 * Issue a link that authorises one passkey enrolment for an existing person.
 *
 * Refuses anybody who is not `active`. Recovering a suspended or offboarded
 * identity would be a way back in that bypasses the decision to take access
 * away — offboarding revokes every passkey, so "restore their passkey" is
 * exactly the shape of the mistake this guard prevents. Reinstating somebody is
 * a status change first, deliberately a separate act.
 *
 * Issuing supersedes any outstanding link for that person, so a mistyped
 * recipient can be corrected by issuing again rather than by hunting for a way
 * to revoke the first one.
 */
export async function createRecovery(input: {
  userId: string
  createdBy: string | null
  ttlHours?: number
}): Promise<CreatedRecovery> {
  const user = await findUserById(input.userId)
  if (!user) throw new RecoveryRefused('no_such_person')
  if (user.status !== 'active') throw new RecoveryRefused('not_active')
  /*
    A role identity has no passkey and never will, so there is nothing to
    recover — and a link that enrolled one would be worse than useless: it would
    hand whoever opened it a credential that signs as the bot, permanently and
    with no human whose absence would ever be noticed (PEEK-34).
  */
  if (user.kind !== 'human') throw new RecoveryRefused('not_a_person')

  await query(
    'update recovery_tokens set consumed_at = now() where user_id = $1 and consumed_at is null',
    [input.userId],
  )

  const token = randomBytes(32).toString('base64url')
  const expiresAt = new Date(Date.now() + (input.ttlHours ?? RECOVERY_TTL_HOURS) * 3600 * 1000)

  const row = await queryOne<{ id: string }>(
    `insert into recovery_tokens (token_hash, user_id, created_by, expires_at)
     values ($1, $2, $3, $4)
     returning id`,
    [sha256(token), input.userId, input.createdBy, expiresAt],
  )
  if (!row) throw new Error('recovery insert returned no row')

  return { id: row.id, token, userId: input.userId, expiresAt }
}

export type RecoveryRejection = 'unknown' | 'expired' | 'consumed' | 'not_active'

export type RecoveryLookup =
  | { ok: true; recovery: RecoveryToken }
  | { ok: false; reason: RecoveryRejection }

/**
 * Resolve a token to the recovery behind it. Read-only; nothing is burned.
 *
 * Re-checks status rather than trusting the check at issuance: an admin can
 * offboard somebody between issuing a link and its being opened, and the later
 * decision has to win. Otherwise a link minted minutes earlier is a way back
 * into an account that was just taken away.
 */
export async function findRecovery(token: string): Promise<RecoveryLookup> {
  const row = await queryOne<{
    id: string
    user_id: string
    expires_at: Date
    consumed: boolean
    expired: boolean
    status: string
  }>(
    `select r.id, r.user_id, r.expires_at,
            r.consumed_at is not null as consumed,
            r.expires_at <= now()     as expired,
            u.status
       from recovery_tokens r
       join users u on u.id = r.user_id
      where r.token_hash = $1`,
    [sha256(token)],
  )

  if (!row) return { ok: false, reason: 'unknown' }
  if (row.consumed) return { ok: false, reason: 'consumed' }
  if (row.expired) return { ok: false, reason: 'expired' }
  if (row.status !== 'active') return { ok: false, reason: 'not_active' }

  return {
    ok: true,
    recovery: { id: row.id, userId: row.user_id, expiresAt: row.expires_at },
  }
}

/**
 * Burn the link, once a passkey actually exists for that person.
 *
 * Conditional on still being unconsumed, so two browsers finishing the ceremony
 * at once cannot both claim it — the same reason challenge consumption is an
 * UPDATE rather than a read then a write.
 */
export async function consumeRecoveryForUser(userId: string): Promise<boolean> {
  const row = await queryOne<{ id: string }>(
    `update recovery_tokens set consumed_at = now()
      where user_id = $1 and consumed_at is null and expires_at > now()
      returning id`,
    [userId],
  )
  return row !== undefined
}

/** Outstanding links, so the people list can show that one is in flight. */
export async function listPendingRecoveries(): Promise<RecoveryToken[]> {
  const result = await query<{ id: string; user_id: string; expires_at: Date }>(
    `select id, user_id, expires_at
       from recovery_tokens
      where consumed_at is null and expires_at > now()
      order by created_at desc`,
  )
  return result.rows.map((row) => ({
    id: row.id,
    userId: row.user_id,
    expiresAt: row.expires_at,
  }))
}
