/**
 * A sign-in lasts while it is used: it ends 7 days after its last use or 14
 * days after the passkey tap, whichever comes first (Miky, 2026-10-16). A bot's
 * delegated sign-in keeps its fixed 24 hours.
 *
 * "Used" is what this service sees: a visit to this origin with the cookie
 * (`/authorize`, the account page) or a renewal at `/token`. The cookie cannot
 * carry the idle end, because a renewal never sends it, so the cookie is set
 * once to the 14-day end and the idle end lives on the session row.
 */
import { createHash, randomBytes } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createSession } from '../../domain/sessions.js'
import { createTestAccount } from '../../domain/test-accounts.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'
import { resetTestLoginRateLimitForTests } from './test-login.js'

const app = createApp()

const REDIRECT = 'https://ship.test/callback'
const CLIENT = 'estiva-ship'
const DAY = 24 * 60 * 60
const HOUR_MS = 60 * 60 * 1000

const post = (path: string, body: Record<string, unknown>) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

/** An app's silent trip to `/authorize?prompt=none`: a code, or `login_required`. */
async function silentSignIn(
  cookie: string,
): Promise<{ code: string | null; error: string | null; verifier: string }> {
  const verifier = randomBytes(32).toString('base64url')
  const params = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: createHash('sha256').update(verifier, 'utf8').digest('base64url'),
    code_challenge_method: 'S256',
    prompt: 'none',
  })
  const response = await app.request(`/authorize?${params.toString()}`, { headers: { cookie } })
  const target = new URL(response.headers.get('location') ?? 'about:blank')
  return {
    code: target.searchParams.get('code'),
    error: target.searchParams.get('error'),
    verifier,
  }
}

/** Sign in silently and redeem the code, returning the first refresh token. */
async function refreshTokenFor(cookie: string): Promise<string> {
  const { code, verifier } = await silentSignIn(cookie)
  const response = await post('/token', {
    grantType: 'authorization_code',
    code,
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeVerifier: verifier,
  })
  return ((await response.json()) as { refresh_token: string }).refresh_token
}

const renew = (refreshToken: string) =>
  post('/token', { grantType: 'refresh_token', refreshToken, clientId: CLIENT })

/** When the app's current refresh token expires: the one in the chain not yet spent. */
async function newestRefreshExpiry(): Promise<Date> {
  const rows = await query<{ expires_at: Date }>(
    'select expires_at from refresh_tokens where used_at is null and revoked_at is null',
  )
  expect(rows.rows).toHaveLength(1)
  return rows.rows[0]?.expires_at as Date
}

const near = (actual: Date, expectedMs: number) =>
  expect(Math.abs(actual.getTime() - expectedMs)).toBeLessThan(60_000)

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  resetTestLoginRateLimitForTests()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [REDIRECT],
    CLIENT,
  ])
})

afterAll(async () => {
  await closePool()
})

describe('a passkey sign-in', () => {
  it('lasts 14 days from the tap in its cookie, and is not re-set when used', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({ userId: ada.id })
    near(session.expiresAt, Date.now() + 14 * DAY * 1000)

    // A use is not a new tap: /authorize answers without touching the cookie.
    const response = await app.request(
      `/authorize?${new URLSearchParams({ client_id: CLIENT, redirect_uri: REDIRECT, response_type: 'code', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', prompt: 'none' })}`,
      { headers: { cookie: `estiva_id_session=${session.token}` } },
    )
    expect(response.headers.get('set-cookie')).toBeNull()
  })

  it('opens an app silently 3 days after the tap when it was last used 2 days ago', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({
      userId: ada.id,
      backdate: { tappedAgoSeconds: 3 * DAY, lastUsedAgoSeconds: 2 * DAY },
    })
    const answer = await silentSignIn(`estiva_id_session=${session.token}`)
    expect(answer.error).toBeNull()
    expect(answer.code).toBeTruthy()
  })

  it('asks for the passkey once it has gone 7 days unused', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({
      userId: ada.id,
      backdate: { tappedAgoSeconds: 8 * DAY, lastUsedAgoSeconds: 7 * DAY + 60 },
    })
    expect((await silentSignIn(`estiva_id_session=${session.token}`)).error).toBe('login_required')
  })

  it('asks for the passkey 14 days after the tap, however recently it was used', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const cookie = `estiva_id_session=${(await createSession({ userId: ada.id })).token}`
    const refreshToken = await refreshTokenFor(cookie)

    // Used a minute ago, every day since the tap — and the tap was 14 days ago.
    await query(
      `update sessions set authenticated_at = now() - interval '14 days 1 minute',
                           expires_at = now() - interval '1 minute',
                           idle_expires_at = now() + interval '7 days'`,
    )
    expect((await silentSignIn(cookie)).error).toBe('login_required')
    expect((await renew(refreshToken)).status).toBe(400)
  })

  it('moves its 7-day idle end forward on every renewal', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({ userId: ada.id })
    const first = await refreshTokenFor(`estiva_id_session=${session.token}`)

    // Five days without a use: two days of idle left.
    await query("update sessions set idle_expires_at = now() + interval '2 days'")
    const renewed = await renew(first)
    expect(renewed.status).toBe(200)

    const row = await query<{ idle_expires_at: Date }>('select idle_expires_at from sessions')
    near(row.rows[0]?.idle_expires_at as Date, Date.now() + 7 * DAY * 1000)
    // The new refresh token lasts as long as the session would if this were its last use.
    near(await newestRefreshExpiry(), Date.now() + 7 * DAY * 1000)

    // And a renewal on day 6 of unused keeps it going: the idle end is per use, not per tap.
    await query("update sessions set idle_expires_at = now() + interval '1 day'")
    const next = (await renewed.json()) as { refresh_token: string }
    expect((await renew(next.refresh_token)).status).toBe(200)
  })

  it('never renews past 14 days from the tap', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({
      userId: ada.id,
      backdate: { tappedAgoSeconds: 12 * DAY, lastUsedAgoSeconds: 0 },
    })
    const first = await refreshTokenFor(`estiva_id_session=${session.token}`)
    expect((await renew(first)).status).toBe(200)

    // Two days left on the 14, seven on the idle end: the earlier one wins.
    near(await newestRefreshExpiry(), session.expiresAt.getTime())
    near(session.expiresAt, Date.now() + 2 * DAY * 1000)
  })

  it('stops renewing once it has gone 7 days unused', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({ userId: ada.id })
    const first = await refreshTokenFor(`estiva_id_session=${session.token}`)
    await query("update sessions set idle_expires_at = now() - interval '1 minute'")
    expect((await renew(first)).status).toBe(400)
  })
})

describe('a bot’s delegated sign-in', () => {
  it('ends 24 hours after it was granted, and renewing it does not extend it', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const session = await createSession({
      userId: ada.id,
      delegate: { clientId: CLIENT, tag: 'test-bot' },
    })
    near(session.expiresAt, Date.now() + 24 * HOUR_MS)

    const first = await refreshTokenFor(`estiva_id_session=${session.token}`)
    expect((await renew(first)).status).toBe(200)
    near(await newestRefreshExpiry(), session.expiresAt.getTime())

    const row = await query<{ expires_at: Date; idle_expires_at: Date | null }>(
      'select expires_at, idle_expires_at from sessions',
    )
    expect(row.rows[0]?.idle_expires_at).toBeNull()
    expect(row.rows[0]?.expires_at.getTime()).toBe(session.expiresAt.getTime())
  })
})

describe('a test account’s back-dated sign-in', () => {
  const login = (body: Record<string, unknown>) => post('/auth/test-login', body)

  it('starts as if tapped and used that long ago, with the cookie ending 14 days after the tap', async () => {
    const qa = await createTestAccount({ email: 'qa-1@example.test', displayName: 'QA-1' })
    const response = await login({
      email: 'qa-1@example.test',
      secret: qa.secret,
      tapped_ago_seconds: 3 * DAY,
      last_used_ago_seconds: 2 * DAY,
    })
    expect(response.status).toBe(200)
    const maxAge = Number(/Max-Age=(\d+)/.exec(response.headers.get('set-cookie') ?? '')?.[1])
    expect(Math.abs(maxAge - 11 * DAY)).toBeLessThan(60)

    const body = (await response.json()) as { expires_at: string }
    near(new Date(body.expires_at), Date.now() + 11 * DAY * 1000)
    const row = await query<{ idle_expires_at: Date }>('select idle_expires_at from sessions')
    near(row.rows[0]?.idle_expires_at as Date, Date.now() + 5 * DAY * 1000)
  })

  it('refuses a last use before the tap', async () => {
    const qa = await createTestAccount({ email: 'qa-1@example.test', displayName: 'QA-1' })
    const response = await login({
      email: 'qa-1@example.test',
      secret: qa.secret,
      tapped_ago_seconds: DAY,
      last_used_ago_seconds: 2 * DAY,
    })
    expect(response.status).toBe(400)
    expect(await query('select 1 from sessions')).toMatchObject({ rowCount: 0 })
  })
})
