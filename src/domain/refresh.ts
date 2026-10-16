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
import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto'
import { config } from '../config.js'
import { query, withTransaction } from '../db/pool.js'
import { liveSessionSql } from './sessions.js'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

/**
 * How long a spent token can be presented again and get the same successor
 * (Miky, 2026-10-16). Long enough for a request that timed out to be retried,
 * short enough that a stolen copy is almost never inside it. See
 * `migrations/013_refresh_retry.sql`.
 */
export const RETRY_SECONDS = 30

const SEAL_INFO = 'estiva-id refresh successor v1'

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
  | {
      ok: true
      userId: string
      sessionId: string
      refreshToken: string
      expiresAt: Date
      /** A retry within {@link RETRY_SECONDS}, answered with the same successor. */
      retried: boolean
    }
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
  /*
    Sealed successors past their window are of no use to anyone; clearing
    them here keeps each one only until the next renewal anyone makes. Its own
    statement, outside the renewal's transaction, so it holds no other chain's
    rows while that transaction waits; `skip locked`: a row another renewal
    holds is cleared by the next one.
  */
  await query(
    `update refresh_tokens set successor_sealed = null
      where id in (select id from refresh_tokens
                    where successor_sealed is not null
                      and used_at <= now() - make_interval(secs => $1)
                      for update skip locked)`,
    [RETRY_SECONDS],
  )

  return withTransaction(async (client) => {
    // One renewal per chain at a time. A retry locks two rows of a chain and a
    // replay revokes all of them; without this the two could take those locks
    // in opposite orders and deadlock, and someone would get a 500.
    await client.query(
      `select pg_advisory_xact_lock(hashtextextended(family_id::text, 0))
         from refresh_tokens where token_hash = $1`,
      [sha256(input.refreshToken)],
    )

    const found = await client.query<{
      id: string
      client_id: string
      user_id: string
      session_id: string
      family_id: string
      expired: boolean
      used: boolean
      revoked: boolean
      successor_sealed: Buffer | null
      in_window: boolean
    }>(
      `select id, client_id, user_id, session_id, family_id,
              expires_at <= now() as expired,
              used_at is not null as used,
              revoked_at is not null as revoked,
              successor_sealed,
              coalesce(used_at > now() - make_interval(secs => $2), false) as in_window
         from refresh_tokens
        where token_hash = $1
          for update`,
      [sha256(input.refreshToken), RETRY_SECONDS],
    )

    const row = found.rows[0]
    if (!row) return { ok: false, reason: 'unknown_token' }

    /**
     * A spent token presented again within 30 seconds, while its successor is
     * unused, is a renewal whose answer was lost: the laptop slept, the Wi-Fi
     * dropped. It gets the same successor it got the
     * first time, so the app stays signed in and the chain still has exactly
     * one live token. The window is Estiva's own policy (Miky, 2026-10-16),
     * on top of RFC 9700 §4.14.2's rotation and reuse detection.
     *
     * The successor is locked too, so it cannot be spent between this check
     * and the answer. Anything else — another app, a revoked chain, a spent
     * successor, a late retry — falls through to reuse below.
     */
    if (
      row.used &&
      row.in_window &&
      !row.revoked &&
      row.successor_sealed &&
      row.client_id === input.clientId
    ) {
      const successor = unsealSuccessor(input.refreshToken, row.id, row.successor_sealed)
      const live = successor
        ? await client.query<{ expires_at: Date; session_live: boolean }>(
            `select expires_at,
                    exists (select 1 from sessions s
                             where s.id = refresh_tokens.session_id and ${liveSessionSql('s')}) as session_live
               from refresh_tokens
              where token_hash = $1 and used_at is null and revoked_at is null
                and expires_at > now()
                for update`,
            [sha256(successor)],
          )
        : undefined
      const next = live?.rows[0]
      if (successor && next) {
        if (!next.session_live) return { ok: false, reason: 'session_gone', userId: row.user_id }
        return {
          ok: true,
          userId: row.user_id,
          sessionId: row.session_id,
          refreshToken: successor,
          expiresAt: next.expires_at,
          retried: true,
        }
      }
    }

    /**
     * Any other consumed token presented again is not a retry — it is two
     * parties holding the same credential, one of whom should not.
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
        `update refresh_tokens set revoked_at = coalesce(revoked_at, now()), successor_sealed = null
          where family_id = $1 and (revoked_at is null or successor_sealed is not null)`,
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

    // The replacement inherits the family, so a later replay of *any* token in
    // the chain still revokes the whole lineage.
    const next = randomBytes(32).toString('base64url')
    const inserted = await client.query<{ id: string }>(
      `insert into refresh_tokens
         (token_hash, client_id, user_id, session_id, family_id, expires_at)
       values ($1, $2, $3, $4, $5, $6)
       returning id`,
      [sha256(next), row.client_id, row.user_id, row.session_id, row.family_id, sessionExpiresAt],
    )

    // Spent, and holding its successor sealed for a retry within the window.
    await client.query(
      `update refresh_tokens set used_at = now(), successor_id = $2, successor_sealed = $3
        where id = $1`,
      [row.id, inserted.rows[0]?.id, sealSuccessor(input.refreshToken, row.id, next)],
    )

    return {
      ok: true,
      userId: row.user_id,
      sessionId: row.session_id,
      refreshToken: next,
      expiresAt: sessionExpiresAt,
      retried: false,
    }
  })
}

/**
 * The key a spent token's successor is sealed under: HKDF over the spent token
 * itself, so only whoever presents it again can open the successor, and the
 * stored SHA-256 of it does not help. Bound to the row by the GCM AAD.
 */
function successorKey(spent: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(spent, 'utf8'), Buffer.alloc(0), SEAL_INFO, 32))
}

function sealSuccessor(spent: string, rowId: string, successor: string): Buffer {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', successorKey(spent), iv)
  cipher.setAAD(Buffer.from(rowId, 'utf8'))
  const sealed = Buffer.concat([cipher.update(successor, 'utf8'), cipher.final()])
  return Buffer.concat([iv, sealed, cipher.getAuthTag()])
}

/** The successor, or null if the box does not open (it always should). */
function unsealSuccessor(spent: string, rowId: string, box: Buffer): string | null {
  try {
    const decipher = createDecipheriv('aes-256-gcm', successorKey(spent), box.subarray(0, 12))
    decipher.setAAD(Buffer.from(rowId, 'utf8'))
    decipher.setAuthTag(box.subarray(box.length - 16))
    return Buffer.concat([
      decipher.update(box.subarray(12, box.length - 16)),
      decipher.final(),
    ]).toString('utf8')
  } catch {
    return null
  }
}
