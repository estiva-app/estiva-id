/**
 * Role and service identities (PEEK-34).
 *
 * A bot, a `support@` address, an agent. What separates these from a person is
 * not what they are allowed to do — that is `role` — but **who the principal
 * is**. For a role there is no human to hold a key, so the org genuinely is the
 * principal and custody is correct forever. For a human, custody is the
 * temporary trade Stage 4 unwinds.
 *
 * Undifferentiated, Stage 4 would have no way to tell which keys to move behind
 * a passkey-PRF wrapper and which are meant to stay where they are — and it
 * would discover the difference by breaking the ones it moved.
 *
 * ## Signing, without a human to sign in
 *
 * `/sign` wants a Bearer token whose subject is a pubkey, and every other route
 * that issues one needs a session. A role has nobody to open one, so it gets
 * the client-credentials grant: an app authenticates as itself and receives a
 * short-lived token for the identity it is registered to act as.
 *
 * The secret is exchanged for a token rather than *being* one, which is what
 * keeps the ten-minute TTL meaningful and leaves nothing long-lived on the
 * wire. It also makes such an app a **confidential client** — so this is for
 * server-side bots only, and a browser app must never be given one, because a
 * secret in a bundle is not a secret.
 */
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { query, queryOne, withTransaction } from '../db/pool.js'
import { getActivePubkey } from './keys.js'
import { type UserWithPubkey, createUserWithKey } from './users.js'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

export class RoleRefused extends Error {
  constructor(readonly reason: 'no_such_identity' | 'not_a_role' | 'not_active' | 'name_taken') {
    super(
      {
        no_such_identity: 'No such identity',
        not_a_role: 'That identity is a person, not a role',
        not_active: 'That identity is not active',
        name_taken: 'A credential with that client id already exists',
      }[reason],
    )
    this.name = 'RoleRefused'
  }
}

/**
 * Create a role identity: a custodied key with no way to sign in.
 *
 * No invite and no passkey, because there is nobody to enrol. The email is
 * optional for the same reason — a bot has no inbox, and requiring one would
 * mean inventing addresses that nothing delivers to.
 */
export async function createRoleIdentity(input: {
  displayName: string
  email?: string | null
}): Promise<UserWithPubkey> {
  return createUserWithKey({
    displayName: input.displayName,
    email: input.email ?? null,
    kind: 'role',
    // A bot is not an admin of the workspace. Nothing today reads `role` for a
    // non-human, but defaulting it to `member` keeps the two axes independent
    // rather than accidentally correlated.
    role: 'member',
  })
}

export interface ServiceCredential {
  clientId: string
  name: string
  actsAsUserId: string
  pubkey: string | null
}

export interface IssuedServiceCredential extends ServiceCredential {
  /** Shown once, at creation. Only its hash is stored. */
  secret: string
}

/**
 * Register a confidential client that signs as a role identity.
 *
 * Re-issuing for the same identity **replaces** the secret rather than adding a
 * second credential: rotation is the common case, and two live secrets for one
 * bot is a state nobody asked for and somebody would have to reason about
 * during an incident.
 */
export async function issueServiceCredential(input: {
  userId: string
  clientId: string
  name: string
  allowedKinds: number[]
  /**
   * Where this credential may mint NIP-98 for, narrowing within the
   * deployment's own allowlist (PEEK-133).
   *
   * Seeded apps get the deployment's prefixes from `db/seed.ts`; a credential
   * minted at runtime had no way to receive any, so every service identity was
   * refused `nip98_url_not_allowed` for kind:27235 — the one kind a bot needs
   * to read the relay bridge at all. Defaults to empty, which is the same
   * fail-closed posture as the column, and means the caller must say where a
   * bot is allowed to authenticate rather than inheriting it by accident.
   */
  nip98UrlPrefixes?: string[]
}): Promise<IssuedServiceCredential> {
  const target = await queryOne<{ kind: string; status: string }>(
    'select kind, status from users where id = $1',
    [input.userId],
  )
  if (!target) throw new RoleRefused('no_such_identity')
  // A credential that signs as a *person* would be a way to act as them without
  // their passkey, which is the thing every other path here is built to prevent.
  if (target.kind !== 'role') throw new RoleRefused('not_a_role')
  if (target.status !== 'active') throw new RoleRefused('not_active')

  const clash = await queryOne<{ acts_as_user_id: string | null }>(
    'select acts_as_user_id from app_credentials where client_id = $1',
    [input.clientId],
  )
  if (clash && clash.acts_as_user_id !== input.userId) throw new RoleRefused('name_taken')

  const secret = randomBytes(32).toString('base64url')

  await withTransaction(async (client) => {
    // Drop any previous credential for this identity, so rotation leaves one.
    await client.query(
      'delete from app_credentials where acts_as_user_id = $1 and client_id <> $2',
      [input.userId, input.clientId],
    )
    // `nip98_url_prefixes` is set on both halves deliberately. Insert alone
    // would leave rotation — the common case, since re-issuing replaces the
    // secret — silently keeping whatever prefixes the row was created with.
    await client.query(
      `insert into app_credentials
         (client_id, name, allowed_kinds, nip98_url_prefixes, client_secret_hash, acts_as_user_id)
       values ($1, $2, $3, $4, $5, $6)
       on conflict (client_id) do update
         set name = excluded.name,
             allowed_kinds = excluded.allowed_kinds,
             nip98_url_prefixes = excluded.nip98_url_prefixes,
             client_secret_hash = excluded.client_secret_hash,
             acts_as_user_id = excluded.acts_as_user_id,
             updated_at = now()`,
      [
        input.clientId,
        input.name,
        input.allowedKinds,
        input.nip98UrlPrefixes ?? [],
        sha256(secret),
        input.userId,
      ],
    )
  })

  return {
    clientId: input.clientId,
    name: input.name,
    actsAsUserId: input.userId,
    pubkey: (await getActivePubkey(input.userId)) ?? null,
    secret,
  }
}

/**
 * Authenticate a confidential client and resolve the identity it acts as.
 *
 * Compared in constant time. A secret check that returns early on the first
 * differing byte leaks its prefix to anybody willing to time the responses,
 * and this one is worth guessing: it signs as the role.
 */
export async function authenticateServiceCredential(
  clientId: string,
  secret: string,
): Promise<ServiceCredential | undefined> {
  const row = await queryOne<{
    client_id: string
    name: string
    client_secret_hash: Buffer | null
    acts_as_user_id: string | null
    status: string
    user_status: string | null
    user_kind: string | null
  }>(
    `select a.client_id, a.name, a.client_secret_hash, a.acts_as_user_id, a.status,
            u.status as user_status, u.kind as user_kind
       from app_credentials a
       left join users u on u.id = a.acts_as_user_id
      where a.client_id = $1`,
    [clientId],
  )

  // A public client — every browser app — has no secret and cannot use this
  // grant however plausible its client_id looks.
  if (!row?.client_secret_hash || !row.acts_as_user_id) return undefined
  if (row.status !== 'active') return undefined

  const presented = sha256(secret)
  if (
    presented.length !== row.client_secret_hash.length ||
    !timingSafeEqual(presented, row.client_secret_hash)
  ) {
    return undefined
  }

  // The identity itself must still be an active role. Offboarding a bot has to
  // stop it signing, and this is where a stateless token would otherwise let it
  // carry on — the same reason `/sign` re-checks the person.
  if (row.user_status !== 'active' || row.user_kind !== 'role') return undefined

  return {
    clientId: row.client_id,
    name: row.name,
    actsAsUserId: row.acts_as_user_id,
    pubkey: (await getActivePubkey(row.acts_as_user_id)) ?? null,
  }
}

/** Every role identity, with whether a credential exists for it. */
export async function listRoleIdentities(): Promise<
  Array<{ id: string; displayName: string | null; pubkey: string | null; clientId: string | null }>
> {
  const result = await query<{
    id: string
    display_name: string | null
    pubkey: string | null
    client_id: string | null
  }>(
    `select u.id, u.display_name, k.pubkey, a.client_id
       from users u
       left join user_keys k on k.user_id = u.id and k.status = 'active'
       left join app_credentials a on a.acts_as_user_id = u.id
      where u.kind = 'role'
      order by u.created_at desc`,
  )
  return result.rows.map((row) => ({
    id: row.id,
    displayName: row.display_name,
    pubkey: row.pubkey,
    clientId: row.client_id,
  }))
}
