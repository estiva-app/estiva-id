/**
 * Delegated sessions: a person's bot holds a session as them (PER-22).
 *
 * The shape is the device authorization grant (RFC 8628) — what `npm login`
 * and `gh auth login` do. The bot authenticates as itself and asks; the person
 * opens a link, sees which bot is asking, and approves with a passkey; the bot
 * collects a session. See `migrations/010_delegated_sessions.sql` for why each
 * constraint on that is there. In short:
 *
 *   * the bot must present its own secret to ask *and* to collect, so a leaked
 *     device code alone is worth nothing;
 *   * only the bot's owner can approve, so a bot can only become the person who
 *     steers it;
 *   * approval is a fresh passkey assertion over a challenge bound to the one
 *     request, not the person's existing cookie;
 *   * the session is marked, and everything minted from it says so.
 */
import { createHash, randomBytes, randomInt } from 'node:crypto'
import { query, queryOne, withTransaction } from '../db/pool.js'
import type { TokenDelegate } from './jwt.js'
import { createSession, liveSessionSql } from './sessions.js'

const sha256 = (input: string) => createHash('sha256').update(input, 'utf8').digest()

/** How long a request waits for the person. RFC 8628's own example is 30 minutes. */
export const DEVICE_REQUEST_TTL_SECONDS = 600

/** How often the bot may poll. RFC 8628 §3.2's default. */
export const POLL_INTERVAL_SECONDS = 5

/**
 * Consonants only, per RFC 8628 §6.1: no vowels means no words, and none of
 * the letters is confusable with a digit. 20^8 codes, and a code is useless
 * without the owner's passkey anyway.
 */
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ'

function generateUserCode(): string {
  let code = ''
  for (let i = 0; i < 8; i++) code += USER_CODE_ALPHABET[randomInt(USER_CODE_ALPHABET.length)]
  return `${code.slice(0, 4)}-${code.slice(4)}`
}

/**
 * What a person typed or followed a link with, in the stored form. Forgiving
 * about case and separators because a person is copying it by hand.
 */
export function normalizeUserCode(input: string): string | undefined {
  const letters = input.toUpperCase().replace(/[^A-Z]/g, '')
  if (letters.length !== 8) return undefined
  if ([...letters].some((ch) => !USER_CODE_ALPHABET.includes(ch))) return undefined
  return `${letters.slice(0, 4)}-${letters.slice(4)}`
}

/**
 * The `client` tag every event signed through the session carries.
 *
 * The bot's client id says exactly which credential; the owner's name makes it
 * readable in a raw event without a lookup — `claude-3f9a1c-as-miky`. The name
 * is already public in the person's `kind:0`; nothing private goes on a relay.
 */
export function delegateTag(botClientId: string, ownerDisplayName: string | null): string {
  const owner =
    (ownerDisplayName ?? '')
      .toLowerCase()
      .split(/\s+/)[0]
      ?.replace(/[^a-z0-9-]/g, '') || 'owner'
  return `${botClientId}-as-${owner}`
}

/**
 * The person a bot belongs to, if it belongs to one and they are active.
 * A workspace-owned role (`Relay Operator`) has no owner, so it has nobody it
 * could ever be granted to act as.
 */
export async function activeOwnerOf(botUserId: string): Promise<string | undefined> {
  const row = await queryOne<{ owner_user_id: string }>(
    `select bot.owner_user_id
       from users bot join users owner on owner.id = bot.owner_user_id
      where bot.id = $1 and owner.status = 'active' and owner.kind = 'human'`,
    [botUserId],
  )
  return row?.owner_user_id
}

export interface StartedRequest {
  deviceCode: string
  userCode: string
  expiresIn: number
  interval: number
}

/**
 * Open a request. The caller has already authenticated the bot and checked it
 * has an owner — this records a decision rather than making one.
 */
export async function startDeviceAuthorization(input: {
  clientId: string
  label?: string | undefined
}): Promise<StartedRequest> {
  const deviceCode = randomBytes(32).toString('base64url')

  // A unique-violation on the user code is astronomically unlikely and cheap to
  // retry; letting it surface as a 500 would not be.
  for (let attempt = 0; attempt < 5; attempt++) {
    const userCode = generateUserCode()
    const inserted = await queryOne<{ id: string }>(
      `insert into device_authorizations (device_code_hash, user_code, client_id, label, expires_at)
       values ($1, $2, $3, $4, now() + make_interval(secs => $5))
       on conflict (user_code) do nothing
       returning id`,
      [
        sha256(deviceCode),
        userCode,
        input.clientId,
        input.label ?? null,
        DEVICE_REQUEST_TTL_SECONDS,
      ],
    )
    if (inserted) {
      return {
        deviceCode,
        userCode,
        expiresIn: DEVICE_REQUEST_TTL_SECONDS,
        interval: POLL_INTERVAL_SECONDS,
      }
    }
  }
  throw new Error('could not allocate a unique user code')
}

export interface DeviceRequest {
  id: string
  userCode: string
  clientId: string
  botName: string
  ownerUserId: string | null
  label: string | null
  status: 'pending' | 'approved' | 'denied' | 'redeemed'
  expired: boolean
  approvalChallenge: string | null
  expiresAt: Date
}

/** A request by the code the person holds, with the bot and owner resolved. */
export async function findDeviceRequest(userCode: string): Promise<DeviceRequest | undefined> {
  const row = await queryOne<{
    id: string
    user_code: string
    client_id: string
    bot_name: string
    owner_user_id: string | null
    label: string | null
    status: DeviceRequest['status']
    expired: boolean
    approval_challenge: string | null
    expires_at: Date
  }>(
    `select d.id, d.user_code, d.client_id, a.name as bot_name, bot.owner_user_id,
            d.label, d.status, d.expires_at <= now() as expired,
            d.approval_challenge, d.expires_at
       from device_authorizations d
       join app_credentials a on a.client_id = d.client_id
       left join users bot on bot.id = a.acts_as_user_id
      where d.user_code = $1`,
    [userCode],
  )
  if (!row) return undefined
  return {
    id: row.id,
    userCode: row.user_code,
    clientId: row.client_id,
    botName: row.bot_name,
    ownerUserId: row.owner_user_id,
    label: row.label,
    status: row.status,
    expired: row.expired,
    approvalChallenge: row.approval_challenge,
    expiresAt: row.expires_at,
  }
}

/** Bind the challenge an approval assertion must sign to this one request. */
export async function setApprovalChallenge(requestId: string, challenge: string): Promise<void> {
  await query(
    `update device_authorizations set approval_challenge = $2
      where id = $1 and status = 'pending'`,
    [requestId, challenge],
  )
}

/**
 * Record the approval. Conditional on the request still being pending and
 * unexpired, so a request cannot be approved twice or after it lapsed.
 */
export async function approveDeviceRequest(input: {
  requestId: string
  userId: string
  credentialRowId: string
}): Promise<boolean> {
  const result = await query(
    `update device_authorizations
        set status = 'approved', approved_by_user_id = $2, approved_credential_id = $3,
            approved_at = now()
      where id = $1 and status = 'pending' and expires_at > now()`,
    [input.requestId, input.userId, input.credentialRowId],
  )
  return (result.rowCount ?? 0) === 1
}

/**
 * Turn a request down. Needs nothing but the code: the worst a stranger holding
 * it can do is stop a bot's pending request, which its owner can simply restart.
 */
export async function denyDeviceRequest(requestId: string): Promise<boolean> {
  const result = await query(
    `update device_authorizations set status = 'denied'
      where id = $1 and status = 'pending'`,
    [requestId],
  )
  return (result.rowCount ?? 0) === 1
}

export type PollFailure =
  | 'authorization_pending'
  | 'slow_down'
  | 'access_denied'
  | 'expired_token'
  | 'invalid_grant'

export type PollResult =
  | {
      ok: true
      userId: string
      sessionId: string
      sessionToken: string
      expiresAt: Date
      tag: string
    }
  | { ok: false; reason: PollFailure; userId?: string }

/**
 * The bot collects its session, exactly once.
 *
 * The request is locked and marked `redeemed` inside one transaction, so two
 * polls racing on an approved request cannot both leave with a session. The
 * session itself is created after that commits: if creating it fails the
 * request is spent and the bot asks again, which is the safe direction.
 *
 * `invalid_grant` covers an unknown device code *and* one presented by a
 * different bot — a caller is not told which.
 */
export async function pollDeviceRequest(input: {
  deviceCode: string
  clientId: string
  userAgent?: string | undefined
}): Promise<PollResult> {
  const claimed = await withTransaction(async (client) => {
    const found = await client.query<{
      id: string
      client_id: string
      status: DeviceRequest['status']
      expired: boolean
      too_soon: boolean
      approved_by_user_id: string | null
      owner_display_name: string | null
    }>(
      `select d.id, d.client_id, d.status, d.expires_at <= now() as expired,
              coalesce(d.last_polled_at > now() - make_interval(secs => $2), false) as too_soon,
              d.approved_by_user_id, owner.display_name as owner_display_name
         from device_authorizations d
         left join users owner on owner.id = d.approved_by_user_id
        where d.device_code_hash = $1
          for update of d`,
      // A second under the interval, so a client polling exactly on time is
      // never told to slow down by clock jitter.
      [sha256(input.deviceCode), POLL_INTERVAL_SECONDS - 1],
    )
    const row = found.rows[0]
    if (!row || row.client_id !== input.clientId) {
      return { ok: false as const, reason: 'invalid_grant' as const }
    }

    await client.query('update device_authorizations set last_polled_at = now() where id = $1', [
      row.id,
    ])

    if (row.status === 'denied') return { ok: false as const, reason: 'access_denied' as const }
    if (row.status === 'redeemed') return { ok: false as const, reason: 'invalid_grant' as const }
    if (row.expired) return { ok: false as const, reason: 'expired_token' as const }
    if (row.status === 'pending') {
      return {
        ok: false as const,
        reason: row.too_soon ? ('slow_down' as const) : ('authorization_pending' as const),
      }
    }

    const userId = row.approved_by_user_id
    if (!userId) return { ok: false as const, reason: 'invalid_grant' as const }

    await client.query(`update device_authorizations set status = 'redeemed' where id = $1`, [
      row.id,
    ])
    return {
      ok: true as const,
      requestId: row.id,
      userId,
      tag: delegateTag(row.client_id, row.owner_display_name),
    }
  })

  if (!claimed.ok) return claimed

  const session = await createSession({
    userId: claimed.userId,
    userAgent: input.userAgent,
    delegate: { clientId: input.clientId, tag: claimed.tag },
  })
  await query('update device_authorizations set session_id = $2 where id = $1', [
    claimed.requestId,
    session.id,
  ])

  return {
    ok: true,
    userId: claimed.userId,
    sessionId: session.id,
    sessionToken: session.token,
    expiresAt: session.expiresAt,
    tag: claimed.tag,
  }
}

export type DelegationCheck =
  | { ok: true; userId: string; tag: string }
  | { ok: false; reason: 'delegation_unknown' | 'delegation_ended' | 'delegate_disabled' }

/**
 * Whether a token's delegation still stands — asked on **every** `/sign`,
 * `/nip44` and directory call a delegated token makes.
 *
 * This is what makes revoking immediate here rather than at token expiry. It
 * also ends the delegation when the bot is retired or its credential disabled,
 * without either path having to know delegated sessions exist.
 */
export async function checkDelegation(delegate: TokenDelegate): Promise<DelegationCheck> {
  const row = await queryOne<{
    user_id: string
    delegate_client_id: string | null
    delegate_tag: string | null
    live: boolean
    credential_status: string | null
    bot_status: string | null
  }>(
    `select s.user_id, s.delegate_client_id, s.delegate_tag,
            ${liveSessionSql('s')} as live,
            a.status as credential_status, bot.status as bot_status
       from sessions s
       left join app_credentials a on a.client_id = s.delegate_client_id
       left join users bot on bot.id = a.acts_as_user_id
      where s.id = $1`,
    [delegate.sessionId],
  )

  // A session that exists but names a different bot — or none — is treated as
  // unknown: the token and the row disagree about who is driving.
  if (!row || row.delegate_client_id !== delegate.clientId || !row.delegate_tag) {
    return { ok: false, reason: 'delegation_unknown' }
  }
  if (!row.live) return { ok: false, reason: 'delegation_ended' }
  if (row.credential_status !== 'active' || row.bot_status !== 'active') {
    return { ok: false, reason: 'delegate_disabled' }
  }
  return { ok: true, userId: row.user_id, tag: row.delegate_tag }
}

/**
 * The tags of an event signed through a delegation: any `client` tag the app
 * set is replaced by the bot's.
 *
 * Replaced rather than appended, so a raw event answers "what composed this"
 * with one value. An app naming itself would otherwise sit beside the bot's
 * tag, and the reader would have to know which one wins.
 */
export function withDelegateTag(tags: string[][], tag: string): string[][] {
  return [...tags.filter((t) => t[0] !== 'client'), ['client', tag]]
}

export interface DelegationSummary {
  /** The session's id — what revoking takes. */
  id: string
  clientId: string
  botName: string
  tag: string
  createdAt: string
  expiresAt: string
  lastSeenAt: string | null
}

/** A person's live delegations, for the account page. */
export async function listDelegations(userId: string): Promise<DelegationSummary[]> {
  const result = await query<{
    id: string
    delegate_client_id: string
    bot_name: string
    delegate_tag: string
    created_at: Date
    expires_at: Date
    last_seen_at: Date | null
  }>(
    `select s.id, s.delegate_client_id, a.name as bot_name, s.delegate_tag,
            s.created_at, s.expires_at, s.last_seen_at
       from sessions s
       join app_credentials a on a.client_id = s.delegate_client_id
      where s.user_id = $1 and s.delegate_client_id is not null
        and ${liveSessionSql('s')}
      order by s.created_at desc`,
    [userId],
  )
  return result.rows.map((row) => ({
    id: row.id,
    clientId: row.delegate_client_id,
    botName: row.bot_name,
    tag: row.delegate_tag,
    createdAt: row.created_at.toISOString(),
    expiresAt: row.expires_at.toISOString(),
    lastSeenAt: row.last_seen_at?.toISOString() ?? null,
  }))
}

/**
 * End one delegation. Scoped to the person, so an id that is not theirs — or
 * not a delegation — revokes nothing and reports so.
 */
export async function revokeDelegation(
  userId: string,
  sessionId: string,
): Promise<{ clientId: string } | undefined> {
  const row = await queryOne<{ delegate_client_id: string }>(
    `update sessions set revoked_at = now()
      where id = $1 and user_id = $2 and delegate_client_id is not null and revoked_at is null
      returning delegate_client_id`,
    [sessionId, userId],
  )
  return row ? { clientId: row.delegate_client_id } : undefined
}
