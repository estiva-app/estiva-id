/**
 * Custodied Nostr keys (PEEK-27).
 *
 * The invariants this module exists to hold:
 *
 *   * A secret key is written **only** as a sealed envelope. There is no code
 *     path that stores it in the clear.
 *   * A secret key is **never returned** from this module. Callers get a
 *     signature, not a key — see {@link withUserSecretKey}.
 *   * A database dump alone does not yield signing keys, because the KEK lives
 *     in the environment.
 */
import type { PoolClient } from 'pg'
import { type Envelope, openEnvelope, sealEnvelope } from '../crypto/envelope.js'
import { query, queryOne } from '../db/pool.js'
import { generateKeypair } from '../nostr/keys.js'
import { currentKek, currentKid, resolveKek } from './kek.js'

interface UserKeyRow {
  pubkey: string
  envelope: Envelope
}

/** AAD binds an envelope to the row that owns it. */
function aadFor(userId: string, pubkey: string): Record<string, string> {
  return { userId, pubkey }
}

/**
 * Mint a keypair for a user and store it sealed.
 *
 * Runs on the caller's transaction so a user can never exist without a key —
 * "on user creation" in PEEK-27 means atomically, not eventually.
 */
export async function mintKeyForUser(client: PoolClient, userId: string): Promise<string> {
  const { publicKeyHex, secretKey } = generateKeypair()
  try {
    const envelope = sealEnvelope({
      secret: secretKey,
      aad: aadFor(userId, publicKeyHex),
      kek: currentKek(),
      kid: currentKid(),
    })
    await client.query('insert into user_keys (user_id, pubkey, envelope) values ($1, $2, $3)', [
      userId,
      publicKeyHex,
      JSON.stringify(envelope),
    ])
    return publicKeyHex
  } finally {
    secretKey.fill(0)
  }
}

export async function getActivePubkey(userId: string): Promise<string | undefined> {
  const row = await queryOne<{ pubkey: string }>(
    "select pubkey from user_keys where user_id = $1 and status = 'active'",
    [userId],
  )
  return row?.pubkey
}

export async function findUserIdByPubkey(pubkey: string): Promise<string | undefined> {
  const row = await queryOne<{ user_id: string }>(
    "select user_id from user_keys where pubkey = $1 and status = 'active'",
    [pubkey],
  )
  return row?.user_id
}

/**
 * Run `use` with the user's decrypted secret key, then zero it.
 *
 * A callback rather than a getter so there is no way to obtain the key and
 * forget to clear it — and so no route handler ever holds one.
 */
export async function withUserSecretKey<T>(
  userId: string,
  use: (secretKey: Buffer, pubkey: string) => T | Promise<T>,
): Promise<T> {
  const row = await queryOne<UserKeyRow>(
    "select pubkey, envelope from user_keys where user_id = $1 and status = 'active'",
    [userId],
  )
  if (!row) throw new Error(`No active key for user ${userId}`)

  const secretKey = openEnvelope({
    envelope: row.envelope,
    aad: aadFor(userId, row.pubkey),
    resolveKek,
  })
  try {
    return await use(secretKey, row.pubkey)
  } finally {
    secretKey.fill(0)
  }
}

/** Which KEK ids are in use, for rotation reporting. Never exposes key material. */
export async function keyCustodyReport(): Promise<{ kid: string; count: number }[]> {
  const result = await query<{ kid: string; count: string }>(
    `select share->>'kid' as kid, count(*)::text as count
       from user_keys, jsonb_array_elements(envelope->'dek'->'shares') as share
      where status = 'active'
      group by 1
      order by 1`,
  )
  return result.rows.map((row) => ({ kid: row.kid, count: Number(row.count) }))
}
