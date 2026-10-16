/**
 * Refresh tokens (PEEK-108).
 *
 * The credential that lets a browser app survive its access token expiring
 * without a top-level redirect. It is the most dangerous thing this service
 * hands to a public client — long-lived, in storage nothing can protect — so
 * almost all of this file is the three properties that make that acceptable:
 * rotation, reuse detection, and session binding.
 *
 * See `migrations/007_refresh_tokens.sql` for why each one is there.
 */
import { createHash, randomBytes } from 'node:crypto'
import { config } from '../config.js'
import { query, withTransaction } from '../db/pool.js'
import { liveSessionSql } from './sessions.js'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

/** When a session ends if nothing uses it again: the earlier of its idle and absolute ends. */
const sessionEndSql = 'least(expires_at, coalesce(idle_expires_at, expires_at))'

export interface IssuedRefreshToken {
  refreshToken: string
  expiresAt: Date
}

/**
 * Mint the first token of a new chain, for a session that has just been proven.
 *
 * The expiry is the **session's**, not a duration of its own. A refresh token
 * that outlived the session that justified it would be a way around session
 * lifetime, which is the same rule `JWT_TTL_SECONDS` already follows.
 */
export async function issueRefreshToken(input: {
  clientId: string
  userId: string
  sessionId: string
}): Promise<IssuedRefreshToken | null> {
  const session = await query<{ ends_at: Date }>(
    `select ${sessionEndSql} as ends_at from sessions
      where id = $1 and ${liveSessionSql()}`,
    [input.sessionId],
  )
  const expiresAt = session.rows[0]?.ends_at
  // No live session means nothing to justify a refresh token. Returning null
  // rather than throwing keeps this a decision the caller reports, not a 500.
  if (!expiresAt) return null

  const token = randomBytes(32).toString('base64url')
  await query(
    `insert into refresh_tokens
       (token_hash, client_id, user_id, session_id, family_id, expires_at)
     values ($1, $2, $3, $4, gen_random_uuid(), $5)`,
    [sha256(token), input.clientId, input.userId, input.sessionId, expiresAt],
  )
  return { refreshToken: token, expiresAt }
}

export type RefreshFailure =
  | 'unknown_token'
  | 'expired'
  | 'revoked'
  | 'reused'
  | 'client_mismatch'
  | 'session_gone'

export type RefreshRedemption =
  | { ok: true; userId: string; sessionId: string; refreshToken: string; expiresAt: Date }
  | { ok: false; reason: RefreshFailure; userId?: string }

/**
 * Exchange a refresh token for the identity behind it, and a fresh one.
 *
 * **The whole operation is one transaction with `for update`**, for the same
 * reason `redeemAuthorizationCode` is: without the lock two simultaneous
 * redemptions could both succeed, and single-use is the property doing the
 * work here.
 *
 * A failure returns a reason rather than throwing, because the caller audits
 * *why*. `reused` in particular is not a bad request, it is an alarm.
 */
export async function redeemRefreshToken(input: {
  refreshToken: string
  clientId: string
}): Promise<RefreshRedemption> {
  return withTransaction(async (client) => {
    const found = await client.query<{
      id: string
      client_id: string
      user_id: string
      session_id: string
      family_id: string
      expired: boolean
      used: boolean
      revoked: boolean
    }>(
      `select id, client_id, user_id, session_id, family_id,
              expires_at <= now() as expired,
              used_at is not null as used,
              revoked_at is not null as revoked
         from refresh_tokens
        where token_hash = $1
          for update`,
      [sha256(input.refreshToken)],
    )

    const row = found.rows[0]
    if (!row) return { ok: false, reason: 'unknown_token' }

    /**
     * A consumed token presented again is not a retry — it is two parties
     * holding the same credential, one of whom should not.
     *
     * There is no way to tell the thief from the victim, so the only safe
     * response is to end the chain: every token in the family is revoked and
     * both are signed out. Refusing just this row would achieve nothing, since
     * it was already spent, and would leave whoever holds the *newest* token in
     * the chain — possibly the attacker — with a working session.
     *
     * This is the reason rotation is worth having at all. Without reuse
     * detection, rotation is bookkeeping.
     */
    if (row.used) {
      await client.query(
        `update refresh_tokens set revoked_at = now()
          where family_id = $1 and revoked_at is null`,
        [row.family_id],
      )
      return { ok: false, reason: 'reused', userId: row.user_id }
    }

    if (row.revoked) return { ok: false, reason: 'revoked', userId: row.user_id }
    if (row.expired) return { ok: false, reason: 'expired', userId: row.user_id }

    // Bound to the app it was issued to. A token leaking to another registered
    // app must not become a session there.
    if (row.client_id !== input.clientId) {
      return { ok: false, reason: 'client_mismatch', userId: row.user_id }
    }

    /**
     * The session is re-checked on every refresh, and this is what makes
     * signing out mean something (PEEK-122). Revoking the session ends refresh
     * immediately, without having to find and revoke rows in this table.
     */
    /*
      The new token ends when the session would if this renewal were its last
      use: 7 days from now for a person's sign-in, never past its 14 days. The
      session itself records the use only once the route has also accepted the
      app and the person (`touchSession`), so a refused renewal keeps nothing
      alive.
    */
    const session = await client.query<{ ends_at: Date }>(
      `select least(expires_at,
                    case when idle_expires_at is null then expires_at
                         else now() + make_interval(secs => $2) end) as ends_at
         from sessions
        where id = $1 and ${liveSessionSql()}`,
      [row.session_id, config().SESSION_IDLE_SECONDS],
    )
    const sessionExpiresAt = session.rows[0]?.ends_at
    if (!sessionExpiresAt) return { ok: false, reason: 'session_gone', userId: row.user_id }

    await client.query('update refresh_tokens set used_at = now() where id = $1', [row.id])

    // The replacement inherits the family, so a later replay of *any* token in
    // the chain still revokes the whole lineage.
    const next = randomBytes(32).toString('base64url')
    await client.query(
      `insert into refresh_tokens
         (token_hash, client_id, user_id, session_id, family_id, expires_at)
       values ($1, $2, $3, $4, $5, $6)`,
      [sha256(next), row.client_id, row.user_id, row.session_id, row.family_id, sessionExpiresAt],
    )

    return {
      ok: true,
      userId: row.user_id,
      sessionId: row.session_id,
      refreshToken: next,
      expiresAt: sessionExpiresAt,
    }
  })
}
