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
import { saveProfile } from './profile.js'
import { type UserWithPubkey, createUserWithKey } from './users.js'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

export class TooManyBots extends Error {
  constructor(readonly limit: number) {
    super(`You already have ${limit} bots. Delete one before making another.`)
    this.name = 'TooManyBots'
  }
}

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
  /**
   * The person this bot belongs to, when it belongs to one.
   *
   * Absent means the workspace's — `Relay Operator` is the case that must stay
   * possible, since it has to outlive whoever set it up. Present means it dies
   * with that person's access (PEEK-164).
   */
  ownerUserId?: string | null
}): Promise<UserWithPubkey> {
  /*
    An owner has to be a human. The mechanism is offboarding, and only a human
    gets offboarded — a bot owned by a bot would be unreachable by the thing
    that is supposed to revoke it. Not expressible as a CHECK, because it is a
    statement about another row, so it is enforced here.
  */
  if (input.ownerUserId) {
    const owner = await queryOne<{ kind: string; status: string }>(
      'select kind, status from users where id = $1',
      [input.ownerUserId],
    )
    if (!owner) throw new RoleRefused('no_such_identity')
    if (owner.kind !== 'human') throw new RoleRefused('not_a_role')
    if (owner.status !== 'active') throw new RoleRefused('not_active')
  }

  return createUserWithKey({
    displayName: input.displayName,
    email: input.email ?? null,
    kind: 'role',
    ownerUserId: input.ownerUserId ?? null,
    // A bot is not an admin of the workspace. Nothing today reads `role` for a
    // non-human, but defaulting it to `member` keeps the two axes independent
    // rather than accidentally correlated.
    role: 'member',
  })
}

/**
 * Rename a role identity, so the relay learns what it is called.
 *
 * A bot's name is not its own to set. A person edits theirs through
 * `PUT /me/profile`, holding a session and a passkey; a role identity has
 * neither, so the only way its name can ever change is an admin acting on it.
 * Without this there was no way at all — `createRoleIdentity` captured a display
 * name once and nothing could revise it afterwards, which is how an agent ended
 * up posting into a team conversation under a name that said nothing about
 * whose it was (PEEK-149).
 *
 * **Refuses a person, for the same reason `issueServiceCredential` does.**
 * Renaming a human through an admin route would let somebody change how another
 * person appears in every app without their key — the thing every other path
 * here exists to prevent — and it would put a second writer on a profile that
 * PEEK-31 deliberately gave one.
 *
 * Saving is all this does. Publishing the `kind:0` is the caller's, because the
 * store is the record and the relay is a projection of it: a relay outage must
 * leave the rename standing and the projection stale, visibly.
 */
export async function renameRoleIdentity(input: {
  userId: string
  displayName: string
}): Promise<{ id: string; displayName: string; previousDisplayName: string | null }> {
  const target = await queryOne<{ kind: string; status: string; display_name: string | null }>(
    'select kind, status, display_name from users where id = $1',
    [input.userId],
  )
  if (!target) throw new RoleRefused('no_such_identity')
  if (target.kind !== 'role') throw new RoleRefused('not_a_role')
  if (target.status !== 'active') throw new RoleRefused('not_active')

  await saveProfile(input.userId, { displayName: input.displayName })

  return {
    id: input.userId,
    displayName: input.displayName,
    previousDisplayName: target.display_name,
  }
}

/**
 * Every role identity belonging to this person.
 *
 * Used by offboarding, which is the only reason ownership is recorded at all:
 * a personal bot has to lose access when its owner does, and nothing else in
 * this service needs to know who owns what (PEEK-164).
 */
export async function botsOwnedBy(
  ownerUserId: string,
): Promise<Array<{ id: string; displayName: string | null }>> {
  const rows = await query<{ id: string; display_name: string | null }>(
    `select id, display_name from users
      where owner_user_id = $1 and kind = 'role' and status != 'offboarded'
      order by created_at`,
    [ownerUserId],
  )
  return rows.rows.map((row) => ({ id: row.id, displayName: row.display_name }))
}

/**
 * How many bots one person may make for themselves.
 *
 * A limit rather than none, because self-service creation mints a relay member
 * and an identity that has to be offboarded later, and neither is free. Five is
 * enough for "one per machine, one for an experiment" and low enough that a
 * runaway script is a support conversation rather than a cleanup.
 */
export const MAX_BOTS_PER_PERSON = 5

/**
 * A globally unique client id that still says what it is.
 *
 * The ticket's own worry: `claude-<handle>` "collides the day two workspaces
 * share a name". A readable prefix plus random suffix keeps the log legible
 * without depending on names being unique anywhere.
 */
function botClientId(label: string): string {
  const slug =
    label
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 24) || 'bot'
  // The column's own shape rule: lowercase, digits, dashes, not dash-initial.
  const prefixed = /^[a-z0-9]/.test(slug) ? slug : `bot-${slug}`
  return `${prefixed}-${randomBytes(3).toString('hex')}`
}

/**
 * Make a bot for yourself — no admin, and no way to give it more than you have.
 *
 * The bottleneck this removes is real: onboarding one more person to the agent
 * needed an admin for three separate steps, and PEEK-163 existed only to make
 * one of them possible at all.
 *
 * Three properties hold it in place, and each is a decision rather than an
 * omission:
 *
 * **It is read-only.** `allowedKinds: [27235]` is NIP-98 HTTP auth and nothing
 * else, so the credential can authenticate and read and cannot publish anything
 * — refused by `/sign` server-side rather than promised. Widening it stays an
 * admin action, which is what keeps "a bot may never exceed its owner" true by
 * construction instead of by review.
 *
 * **Its name cannot lie.** Composed here rather than taken from the caller, so
 * every bot says whose it is. A message in a Peek conversation renders exactly
 * like a colleague (PEEK-171), and a person naming their own bot "Support" is
 * one careless moment away from a chat nobody can attribute.
 *
 * **It dies with its owner.** `owner_user_id` is what `offboardPerson` cascades
 * over, so a bot created here cannot outlive the access of the person who made
 * it — which is the property that made self-service safe to offer at all.
 */
export async function createOwnBot(input: {
  ownerUserId: string
  /** What the person calls it. The owner's name is appended, not trusted to it. */
  label: string
}): Promise<IssuedServiceCredential & { botUserId: string; displayName: string }> {
  const owner = await queryOne<{ kind: string; status: string; display_name: string | null }>(
    'select kind, status, display_name from users where id = $1',
    [input.ownerUserId],
  )
  if (!owner) throw new RoleRefused('no_such_identity')
  if (owner.kind !== 'human') throw new RoleRefused('not_a_role')
  if (owner.status !== 'active') throw new RoleRefused('not_active')

  const existing = await botsOwnedBy(input.ownerUserId)
  if (existing.length >= MAX_BOTS_PER_PERSON) throw new TooManyBots(MAX_BOTS_PER_PERSON)

  /*
    "steered by" rather than "for" or "of": PEEK-171 settled that the name has
    to answer "who is behind this message" to somebody reading a conversation,
    not merely "who owns this row".
  */
  const displayName = `${input.label} (steered by ${owner.display_name ?? 'their owner'})`

  const bot = await createRoleIdentity({ displayName, ownerUserId: input.ownerUserId })
  const credential = await issueServiceCredential({
    userId: bot.id,
    clientId: botClientId(input.label),
    name: displayName,
    // Read-only by construction. See above.
    allowedKinds: [27235],
  })

  return { ...credential, botUserId: bot.id, displayName }
}

/**
 * Stop one of your own bots, for good.
 *
 * **Offboarding, not deletion**, and the word matters after PEEK-170: calling
 * something Delete when it does not delete is how somebody ends up believing a
 * thing is gone while it is still readable. What actually happens here is that
 * the bot's identity is offboarded — it can never mint another token, its key
 * stops being admitted to the relay — and everything it already wrote stays
 * exactly where it is, attributed to it, the same way a person's messages
 * outlast their account.
 *
 * The credential row is left in place for the same reason `offboardPerson`
 * leaves it: deleting it would let a re-issue silently recreate access under
 * the same client id, and the audit trail would lose what the bot was.
 *
 * Ownership is checked here rather than in the route, because the subject alone
 * decides it — a caller who is not the owner must be refused whether the
 * request came from the console, a script, or a future caller nobody has
 * written yet.
 */
export async function retireOwnBot(input: {
  ownerUserId: string
  botUserId: string
}): Promise<{ displayName: string | null }> {
  const bot = await queryOne<{
    kind: string
    status: string
    display_name: string | null
    owner_user_id: string | null
  }>('select kind, status, display_name, owner_user_id from users where id = $1', [input.botUserId])
  if (!bot) throw new RoleRefused('no_such_identity')
  if (bot.kind !== 'role') throw new RoleRefused('not_a_role')
  /*
    Somebody else's bot, or the workspace's, is `no_such_identity` rather than a
    refusal that confirms it exists. A person poking at ids should not learn
    which ones are real.
  */
  if (bot.owner_user_id !== input.ownerUserId) throw new RoleRefused('no_such_identity')
  if (bot.status !== 'active') throw new RoleRefused('not_active')

  return { displayName: bot.display_name }
}

/**
 * Change what a credential may sign, without replacing the secret.
 *
 * There was no way to do this. `issueServiceCredential` upserts
 * `client_secret_hash` along with `allowed_kinds`, so the only route to a wider
 * ceiling was re-issuing — which **rotates the secret** and breaks every copy
 * of it: the file on a laptop, the value in Claude Desktop's keychain, whatever
 * a colleague pasted into their own setup.
 *
 * That coupling made a routine change expensive enough to avoid, which is how
 * `peek create-topic` shipped against a ceiling nobody wanted to touch. A
 * capability change and a credential rotation are different decisions and
 * should not be the same operation.
 *
 * Still an admin action, and deliberately so: this is the one control standing
 * between an agent and the whole workspace (PEEK-145 settled that there is no
 * Folder boundary behind it), so widening is exactly the thing a member must
 * not be able to do for their own bot.
 */
export async function setCredentialKinds(input: {
  clientId: string
  allowedKinds: number[]
}): Promise<{ clientId: string; from: number[]; to: number[] }> {
  const row = await queryOne<{
    allowed_kinds: number[]
    acts_as_user_id: string | null
    status: string
  }>('select allowed_kinds, acts_as_user_id, status from app_credentials where client_id = $1', [
    input.clientId,
  ])
  if (!row) throw new RoleRefused('no_such_identity')
  if (row.status !== 'active') throw new RoleRefused('not_active')

  await query(
    'update app_credentials set allowed_kinds = $2, updated_at = now() where client_id = $1',
    [input.clientId, input.allowedKinds],
  )

  return { clientId: input.clientId, from: row.allowed_kinds, to: input.allowedKinds }
}

export interface ServiceCredential {
  clientId: string
  name: string
  actsAsUserId: string
  pubkey: string | null
  /**
   * The kinds this credential may sign, returned so a caller can be told.
   *
   * Selected here rather than fetched separately because the row is already
   * open — and because a second query would be a second chance to forget.
   */
  allowedKinds: number[]
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
    allowedKinds: input.allowedKinds,
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
    allowed_kinds: number[]
    status: string
    user_status: string | null
    user_kind: string | null
  }>(
    `select a.client_id, a.name, a.client_secret_hash, a.acts_as_user_id, a.allowed_kinds, a.status,
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
    allowedKinds: row.allowed_kinds,
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
