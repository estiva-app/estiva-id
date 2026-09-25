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

/**
 * Who holds a session that is not the person's own (PER-22).
 *
 * `clientId` is the bot's service credential; `tag` is the `client` tag `/sign`
 * adds to every event signed through it. See `domain/delegation.ts`.
 */
export interface SessionDelegate {
  clientId: string
  tag: string
}

export interface Session {
  id: string
  userId: string
  /** Absent for the person's own session — every session before PER-22. */
  delegate?: SessionDelegate | undefined
}

function hashToken(token: string): Buffer {
  return createHash('sha256').update(token, 'utf8').digest()
}

export async function createSession(input: {
  userId: string
  credentialId?: string | undefined
  userAgent?: string | undefined
  /** Makes this a delegated session, with its own, shorter lifetime. */
  delegate?: SessionDelegate | undefined
}): Promise<{ id: string; token: string; expiresAt: Date }> {
  const cfg = config()
  const token = randomBytes(32).toString('base64url')
  const ttl = input.delegate ? cfg.DELEGATED_SESSION_TTL_SECONDS : cfg.SESSION_TTL_SECONDS
  const expiresAt = new Date(Date.now() + ttl * 1000)

  const row = await queryOne<{ id: string }>(
    `insert into sessions
       (user_id, token_hash, credential_id, expires_at, user_agent, delegate_client_id, delegate_tag)
     values ($1, $2, $3, $4, $5, $6, $7)
     returning id`,
    [
      input.userId,
      hashToken(token),
      input.credentialId ?? null,
      expiresAt,
      input.userAgent ?? null,
      input.delegate?.clientId ?? null,
      input.delegate?.tag ?? null,
    ],
  )
  if (!row) throw new Error('session insert returned nothing')
  return { id: row.id, token, expiresAt }
}

interface SessionRow {
  id: string
  user_id: string
  delegate_client_id: string | null
  delegate_tag: string | null
}

function toSession(row: SessionRow): Session {
  return {
    id: row.id,
    userId: row.user_id,
    delegate:
      row.delegate_client_id && row.delegate_tag
        ? { clientId: row.delegate_client_id, tag: row.delegate_tag }
        : undefined,
  }
}

/** Resolve a session token, or undefined if absent, expired or revoked. */
export async function resolveSession(token: string): Promise<Session | undefined> {
  const row = await queryOne<SessionRow>(
    `update sessions
        set last_seen_at = now()
      where token_hash = $1
        and revoked_at is null
        and expires_at > now()
      returning id, user_id, delegate_client_id, delegate_tag`,
    [hashToken(token)],
  )
  return row ? toSession(row) : undefined
}

/**
 * A session by id, **live or not** — for the grants that carry a session id
 * rather than a cookie (the code and refresh grants).
 *
 * Returned whatever its state, with `live` beside it, because the question
 * those grants ask is "was this a bot's?" first. A lookup that answered nothing
 * for an ended session would make an ended delegation indistinguishable from a
 * person's own session, and the token would come out without `act`.
 */
export async function findSessionById(
  sessionId: string,
): Promise<(Session & { live: boolean }) | undefined> {
  const row = await queryOne<SessionRow & { live: boolean }>(
    `select id, user_id, delegate_client_id, delegate_tag,
            (revoked_at is null and expires_at > now()) as live
       from sessions where id = $1`,
    [sessionId],
  )
  return row ? { ...toSession(row), live: row.live } : undefined
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
