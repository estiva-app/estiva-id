/**
 * Test accounts: people with nobody behind them (PER-22).
 *
 * QA-1 and QA-2 let the agent reproduce what a person sees without acting as a
 * real one. Everything outside this service sees an ordinary member — no bot
 * flag, no marker — so what they do lands exactly as a colleague's would. The
 * only difference is that they sign in with a secret, and the schema lets only
 * a test account hold one (`migrations/011_test_accounts.sql`).
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { query, queryOne } from '../db/pool.js'
import { publishProfile, saveProfile } from './profile.js'
import { admitMember } from './relay-membership.js'
import { createUserWithKey, findUserByEmail } from './users.js'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

/** Replace a test account's secret, returning the new one. Shown once. */
export async function issueTestSecret(userId: string): Promise<string> {
  const secret = randomBytes(32).toString('base64url')
  // The composite foreign key refuses this for anybody who is not a test
  // account, so a mistaken user id fails here rather than minting a password.
  await query(
    `insert into test_credentials (user_id, secret_hash) values ($1, $2)
     on conflict (user_id) do update
       set secret_hash = excluded.secret_hash, created_at = now(), revoked_at = null`,
    [userId, sha256(secret)],
  )
  return secret
}

export interface CreatedTestAccount {
  userId: string
  pubkey: string
  secret: string
  admitted: boolean | string
  published: boolean | string
}

/**
 * Create a test account the way enrolment creates a person: a key, admission
 * to the relay, then the profile — in that order, because a `kind:0` from a
 * pubkey the relay does not admit is dropped.
 */
export async function createTestAccount(input: {
  email: string
  displayName: string
  handle?: string | undefined
}): Promise<CreatedTestAccount> {
  if (await findUserByEmail(input.email)) throw new Error(`${input.email} already exists`)

  const user = await createUserWithKey({
    email: input.email,
    displayName: input.displayName,
    role: 'member',
    kind: 'human',
    testAccount: true,
  })
  const secret = await issueTestSecret(user.id)
  if (input.handle) await saveProfile(user.id, { handle: input.handle })

  const admission = await admitMember(user.pubkey)
  const profile = admission.ok ? await publishProfile(user.id) : undefined

  return {
    userId: user.id,
    pubkey: user.pubkey,
    secret,
    admitted: admission.ok ? true : (admission.reason ?? 'unknown'),
    published: profile
      ? profile.published
        ? true
        : (profile.reason ?? 'unknown')
      : 'not_admitted',
  }
}

export type TestSignInFailure = 'unknown' | 'not_active' | 'bad_secret'

/**
 * Check a test account's secret. The caller answers every failure the same;
 * the reason is for the audit log.
 */
export async function authenticateTestAccount(
  email: string,
  secret: string,
): Promise<
  { ok: true; userId: string } | { ok: false; reason: TestSignInFailure; userId?: string }
> {
  const row = await queryOne<{ id: string; status: string; secret_hash: Buffer }>(
    `select u.id, u.status, t.secret_hash
       from users u join test_credentials t on t.user_id = u.id
      where lower(u.email) = lower($1) and u.test_account and t.revoked_at is null`,
    [email],
  )
  if (!row) return { ok: false, reason: 'unknown' }

  const presented = sha256(secret)
  if (presented.length !== row.secret_hash.length || !timingSafeEqual(presented, row.secret_hash)) {
    return { ok: false, reason: 'bad_secret', userId: row.id }
  }
  // After the secret, so an unauthenticated caller cannot learn an account's status.
  if (row.status !== 'active') return { ok: false, reason: 'not_active', userId: row.id }
  return { ok: true, userId: row.id }
}
