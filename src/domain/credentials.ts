/**
 * Passkey credentials.
 *
 * **Multiple credentials per user from day one** (PEEK-26). One passkey per
 * person is a support incident waiting to happen: a lost laptop should be an
 * inconvenience, not an identity loss, and enrolling a second device has to be
 * possible before anyone needs it.
 *
 * The passkey is an *authenticator*, not a key-wrapper. Wrapping the Nostr key
 * with passkey-PRF is Stage 4; keeping the two apart is what lets Stage 1 ship
 * without forcing client-side signing.
 */
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import { query, queryOne } from '../db/pool.js'

export interface StoredCredential {
  id: string
  userId: string
  credentialId: string
  publicKey: Uint8Array<ArrayBuffer>
  signCount: number
  transports: string[]
}

interface CredentialRow {
  id: string
  user_id: string
  credential_id: Buffer
  public_key: Buffer
  sign_count: string
  transports: string[]
}

// `Uint8Array.from` rather than `new Uint8Array(buffer)`: pg hands back
// `Buffer`, whose backing store is typed `ArrayBufferLike`, and SimpleWebAuthn
// asks for `Uint8Array<ArrayBuffer>`. Copying settles the variance honestly
// instead of casting it away.
function toStored(row: CredentialRow): StoredCredential {
  return {
    id: row.id,
    userId: row.user_id,
    credentialId: isoBase64URL.fromBuffer(Uint8Array.from(row.credential_id)),
    publicKey: Uint8Array.from(row.public_key),
    signCount: Number(row.sign_count),
    transports: row.transports,
  }
}

export async function insertCredential(input: {
  userId: string
  credentialId: string
  publicKey: Uint8Array
  signCount: number
  transports: string[]
  aaguid?: string | undefined
  backedUp: boolean
  deviceType?: string | undefined
  nickname?: string | undefined
}): Promise<string> {
  const row = await queryOne<{ id: string }>(
    `insert into webauthn_credentials
       (user_id, credential_id, public_key, sign_count, transports, aaguid,
        backed_up, device_type, nickname)
     values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     returning id`,
    [
      input.userId,
      isoBase64URL.toBuffer(input.credentialId),
      Buffer.from(input.publicKey),
      input.signCount,
      input.transports,
      input.aaguid ?? null,
      input.backedUp,
      input.deviceType ?? null,
      input.nickname ?? null,
    ],
  )
  if (!row) throw new Error('credential insert returned no row')
  return row.id
}

/** Look up by the credential id the authenticator returned. Revoked rows are invisible. */
export async function findActiveCredential(
  credentialId: string,
): Promise<StoredCredential | undefined> {
  const row = await queryOne<CredentialRow>(
    `select id, user_id, credential_id, public_key, sign_count, transports
       from webauthn_credentials
      where credential_id = $1 and revoked_at is null`,
    [isoBase64URL.toBuffer(credentialId)],
  )
  return row ? toStored(row) : undefined
}

export async function listActiveCredentials(userId: string): Promise<StoredCredential[]> {
  const result = await query<CredentialRow>(
    `select id, user_id, credential_id, public_key, sign_count, transports
       from webauthn_credentials
      where user_id = $1 and revoked_at is null
      order by created_at`,
    [userId],
  )
  return result.rows.map(toStored)
}

export interface CredentialSummary {
  id: string
  nickname: string | null
  deviceType: string | null
  backedUp: boolean
  transports: string[]
  createdAt: string
  lastUsedAt: string | null
}

/** What a user may see about their own passkeys. No public keys, no raw ids. */
export async function listCredentialSummaries(userId: string): Promise<CredentialSummary[]> {
  const result = await query<{
    id: string
    nickname: string | null
    device_type: string | null
    backed_up: boolean
    transports: string[]
    created_at: Date
    last_used_at: Date | null
  }>(
    `select id, nickname, device_type, backed_up, transports, created_at, last_used_at
       from webauthn_credentials
      where user_id = $1 and revoked_at is null
      order by created_at`,
    [userId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    nickname: row.nickname,
    deviceType: row.device_type,
    backedUp: row.backed_up,
    transports: row.transports,
    createdAt: row.created_at.toISOString(),
    lastUsedAt: row.last_used_at?.toISOString() ?? null,
  }))
}

export async function countActiveCredentials(userId: string): Promise<number> {
  const row = await queryOne<{ count: string }>(
    'select count(*)::text as count from webauthn_credentials where user_id = $1 and revoked_at is null',
    [userId],
  )
  return Number(row?.count ?? 0)
}

/**
 * Does this credential belong to this user and is it still active?
 *
 * Asked before the last-passkey rule, so that trying to revoke someone else's
 * credential is answered as "no such credential of yours" rather than leaking a
 * fact about their account through a different refusal.
 */
export async function ownsActiveCredential(
  userId: string,
  credentialRowId: string,
): Promise<boolean> {
  const row = await queryOne<{ id: string }>(
    'select id from webauthn_credentials where id = $1 and user_id = $2 and revoked_at is null',
    [credentialRowId, userId],
  )
  return row !== undefined
}

/**
 * Revoke one of the user's own credentials.
 *
 * Scoped by `user_id` in the WHERE clause, so a caller cannot revoke someone
 * else's passkey by guessing an id.
 */
export async function revokeCredential(userId: string, credentialRowId: string): Promise<boolean> {
  const result = await query(
    `update webauthn_credentials set revoked_at = now()
      where id = $1 and user_id = $2 and revoked_at is null`,
    [credentialRowId, userId],
  )
  return (result.rowCount ?? 0) > 0
}

/**
 * Record a successful authentication.
 *
 * A counter that fails to advance is how a cloned authenticator shows itself.
 * Authenticators that always report 0 are common and are not treated as clones.
 */
export async function recordCredentialUse(
  credentialRowId: string,
  newSignCount: number,
): Promise<void> {
  await query(
    'update webauthn_credentials set sign_count = $2, last_used_at = now() where id = $1',
    [credentialRowId, newSignCount],
  )
}
