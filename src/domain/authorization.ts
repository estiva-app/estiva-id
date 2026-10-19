/**
 * Authorization codes with PKCE (PEEK-90).
 *
 * The bridge between "signed in on this origin" and "an app on another origin
 * holds a token", and the only one: `POST /token` takes no session cookie. The
 * cookie could not cross origins anyway — it is `SameSite=Lax` and `/token`
 * allows no credentials — and neither of those should be relaxed on the origin
 * that holds every custodied signing key.
 *
 * A code is a bearer credential in transit through a browser redirect, so it is
 * treated like one: hashed at rest, expiring in a minute, usable once, and
 * bound to the app, the person, the destination and a proof of possession.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { query, queryOne, withTransaction } from '../db/pool.js'

/**
 * How long a code stays redeemable.
 *
 * One minute. The code's whole life is a redirect and an immediate exchange —
 * RFC 6749 recommends a maximum of ten, which is generous for a machine-to-
 * machine round trip and is ten minutes of exposure for something sitting in
 * browser history.
 */
export const CODE_TTL_SECONDS = 60

/** The only challenge method accepted. */
export const CODE_CHALLENGE_METHOD = 'S256'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

/** base64url(sha256(verifier)) — RFC 7636 §4.2. */
export function deriveChallenge(codeVerifier: string): string {
  return sha256(codeVerifier).toString('base64url')
}

export interface IssuedCode {
  code: string
  expiresAt: Date
}

/**
 * Mint a code for a person who has already authenticated on this origin.
 *
 * The caller is responsible for having checked the app, the redirect URI and
 * the person's status — this records a decision that has already been made
 * rather than making one.
 */
export async function issueAuthorizationCode(input: {
  clientId: string
  userId: string
  redirectUri: string
  codeChallenge: string
  /**
   * The session that approved this. Carried across the redirect so a refresh
   * token minted at redemption can inherit the binding (PEEK-108) — this is the
   * only moment the session is known.
   */
  sessionId: string
}): Promise<IssuedCode> {
  const code = randomBytes(32).toString('base64url')
  const expiresAt = new Date(Date.now() + CODE_TTL_SECONDS * 1000)

  await query(
    `insert into authorization_codes
       (code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at, session_id)
     values ($1, $2, $3, $4, $5, $6, $7)`,
    [
      sha256(code),
      input.clientId,
      input.userId,
      input.redirectUri,
      input.codeChallenge,
      expiresAt,
      input.sessionId,
    ],
  )
  return { code, expiresAt }
}

export type RedemptionFailure =
  | 'unknown_code'
  | 'expired'
  | 'already_used'
  | 'client_mismatch'
  | 'redirect_uri_mismatch'
  | 'verifier_mismatch'

export type Redemption =
  /** `sessionId` is absent for a code issued before PEEK-108 — see the migration. */
  | { ok: true; userId: string; clientId: string; sessionId: string | null }
  | { ok: false; reason: RedemptionFailure; userId?: string }

/**
 * Exchange a code for the identity behind it, exactly once.
 *
 * **The consume is inside the transaction that reads it**, with `for update`,
 * so two simultaneous redemptions cannot both succeed. Without the lock, PKCE
 * still holds but single-use does not, and single-use is what makes a stolen
 * code useless after the legitimate app has already redeemed it.
 *
 * A failure returns a reason rather than throwing, because the caller has to
 * audit *why* — `already_used` is a replay and worth noticing, while `expired`
 * is a slow network.
 */
export async function redeemAuthorizationCode(input: {
  code: string
  clientId: string
  redirectUri: string
  codeVerifier: string
}): Promise<Redemption> {
  return withTransaction(async (client) => {
    const found = await client.query<{
      id: string
      client_id: string
      user_id: string
      redirect_uri: string
      code_challenge: string
      session_id: string | null
      expired: boolean
      consumed: boolean
    }>(
      `select id, client_id, user_id, redirect_uri, code_challenge, session_id,
              expires_at <= now() as expired,
              consumed_at is not null as consumed
         from authorization_codes
        where code_hash = $1
          for update`,
      [sha256(input.code)],
    )

    const row = found.rows[0]
    if (!row) return { ok: false, reason: 'unknown_code' }

    // Burn it on any outcome past this point. A code that was presented at all
    // has been in the wild; leaving a failed attempt redeemable would let an
    // attacker retry a stolen code against different verifiers.
    await client.query('update authorization_codes set consumed_at = now() where id = $1', [row.id])

    if (row.consumed) return { ok: false, reason: 'already_used', userId: row.user_id }
    if (row.expired) return { ok: false, reason: 'expired', userId: row.user_id }
    if (row.client_id !== input.clientId) {
      return { ok: false, reason: 'client_mismatch', userId: row.user_id }
    }
    if (row.redirect_uri !== input.redirectUri) {
      return { ok: false, reason: 'redirect_uri_mismatch', userId: row.user_id }
    }

    // Constant-time, because this is the check standing between a stolen code
    // and a token. Length is compared first — timingSafeEqual throws on a
    // mismatch, and the length of a base64url SHA-256 is not a secret.
    const expected = Buffer.from(row.code_challenge, 'utf8')
    const presented = Buffer.from(deriveChallenge(input.codeVerifier), 'utf8')
    const matches = expected.length === presented.length && timingSafeEqual(expected, presented)
    if (!matches) return { ok: false, reason: 'verifier_mismatch', userId: row.user_id }

    return {
      ok: true,
      userId: row.user_id,
      clientId: row.client_id,
      sessionId: row.session_id,
    }
  })
}

/**
 * Drop codes that can no longer be redeemed.
 *
 * Not wired to a schedule. Consumed and expired rows are harmless — they hold
 * no secret, only a hash — but they accumulate, and a replay attempt against a
 * *deleted* code reports `unknown_code` rather than `already_used`, which loses
 * the signal. Retain longer than you think; this exists for when the table
 * becomes large rather than for hygiene.
 */
export async function purgeDeadAuthorizationCodes(olderThanHours = 24): Promise<number> {
  const result = await query(
    `delete from authorization_codes
      where created_at < now() - make_interval(hours => $1)`,
    [olderThanHours],
  )
  return result.rowCount ?? 0
}

/**
 * Whether any registered redirect URI lives on this origin.
 *
 * Governs CORS on `/token` — see the middleware. Deriving it from the redirect
 * allowlist rather than a second setting means there is one place that says
 * which origins this service will talk to, and it cannot drift.
 */
export async function isRegisteredRedirectOrigin(origin: string): Promise<boolean> {
  const row = await queryOne<{ ok: boolean }>(
    `select exists (
       select 1 from app_credentials, unnest(redirect_uris) as uri
        where status = 'active' and uri like $1
     ) as ok`,
    // Anchored with the separator so `https://app.test` cannot match
    // `https://app.test.attacker.example/cb`.
    [`${origin}/%`],
  )
  return row?.ok === true
}

/** Whether an app may be redirected to this exact URI. */
export async function isRegisteredRedirectUri(
  clientId: string,
  redirectUri: string,
): Promise<boolean> {
  const row = await queryOne<{ ok: boolean }>(
    'select $2 = any(redirect_uris) as ok from app_credentials where client_id = $1',
    [clientId, redirectUri],
  )
  return row?.ok === true
}
