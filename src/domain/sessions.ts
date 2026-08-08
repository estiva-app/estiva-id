/**
 * Browser sessions on the identity origin.
 *
 * The session is an opaque random token in an httpOnly cookie. Only its SHA-256
 * hash is stored, so a database dump does not hand over live sessions — the
 * same reasoning that keeps secret keys sealed.
 *
 * This is *not* the token other apps consume. Apps get a short-lived JWT
 * (PEEK-29); the session is what lets a browser ask for one.
 */
import { createHash, randomBytes } from 'node:crypto'
import { config } from '../config.js'
import { query, queryOne } from '../db/pool.js'

export const SESSION_COOKIE = 'estiva_id_session'

export interface Session {
  id: string
  userId: string
}

function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest()
}

export async function createSession(input: {
  userId: string
  credentialId?: string | undefined
  userAgent?: string | undefined
}): Promise<{ token: string; expiresAt: Date }> {
  const token = randomBytes(32).toString('base64url')
  const expiresAt = new Date(Date.now() + config().SESSION_TTL_SECONDS * 1000)

  await query(
    `insert into sessions (user_id, token_hash, credential_id, expires_at, user_agent)
     values ($1, $2, $3, $4, $5)`,
    [
      input.userId,
      hashToken(token),
      input.credentialId ?? null,
      expiresAt,
      input.userAgent ?? null,
    ],
  )
  return { token, expiresAt }
}

/** Resolve a session token, or undefined if absent, expired or revoked. */
export async function resolveSession(token: string): Promise<Session | undefined> {
  const row = await queryOne<{ id: string; user_id: string }>(
    `update sessions
        set last_seen_at = now()
      where token_hash = $1
        and revoked_at is null
        and expires_at > now()
      returning id, user_id`,
    [hashToken(token)],
  )
  return row ? { id: row.id, userId: row.user_id } : undefined
}

export async function revokeSession(token: string): Promise<void> {
  await query(
    'update sessions set revoked_at = now() where token_hash = $1 and revoked_at is null',
    [hashToken(token)],
  )
}

/** Sign out everywhere — used by offboarding and by "revoke my other sessions". */
export async function revokeAllSessions(userId: string): Promise<number> {
  const result = await query(
    'update sessions set revoked_at = now() where user_id = $1 and revoked_at is null',
    [userId],
  )
  return result.rowCount ?? 0
}

/**
 * Sign out everywhere *except here*.
 *
 * The self-serve version of the above, and deliberately not the same call.
 * Offboarding wants every session gone including the leaver's current one;
 * a person clicking "sign out my other devices" after losing a laptop does
 * not want to be signed out of the page they are clicking in. Reusing
 * {@link revokeAllSessions} for both would make the safe action feel like a
 * malfunction, and the natural fix — logging back in — is exactly what someone
 * with a stolen cookie would also be able to do.
 */
export async function revokeOtherSessions(userId: string, keepSessionId: string): Promise<number> {
  const result = await query(
    `update sessions set revoked_at = now()
      where user_id = $1 and id <> $2 and revoked_at is null`,
    [userId, keepSessionId],
  )
  return result.rowCount ?? 0
}
