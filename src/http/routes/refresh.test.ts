/**
 * PEEK-108 acceptance: a browser app can outlive its access token without a
 * redirect, and the credential that lets it is not a hole.
 *
 * The happy path here is two lines. Everything else is the reason a long-lived
 * bearer credential in a public client is acceptable at all: it rotates, a
 * replay burns the chain, and it is only as alive as the session behind it.
 */
import { createHash, randomBytes } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createSession, revokeSession } from '../../domain/sessions.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

const REDIRECT = 'https://ship.test/callback'
const CLIENT = 'estiva-ship'

function pkce() {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url')
  return { verifier, challenge }
}

const post = (body: Record<string, unknown>) =>
  app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

interface TokenBody {
  access_token?: string
  refresh_token?: string
  expires_in?: number
}

/** Run the browser half and redeem, returning the first refresh token. */
async function signIn(cookie: string): Promise<TokenBody> {
  const { verifier, challenge } = pkce()
  const params = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  const authorized = await app.request(`/authorize?${params.toString()}`, { headers: { cookie } })
  const code = new URL(authorized.headers.get('location') ?? '').searchParams.get('code')
  const response = await post({
    grantType: 'authorization_code',
    code,
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeVerifier: verifier,
  })
  return (await response.json()) as TokenBody
}

const refresh = (refreshToken: string, clientId = CLIENT) =>
  post({ grantType: 'refresh_token', refreshToken, clientId })

let ada: Awaited<ReturnType<typeof createUserWithKey>>
let sessionToken: string
let cookie: string

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [REDIRECT],
    CLIENT,
  ])
  ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
  const session = await createSession({ userId: ada.id })
  sessionToken = session.token
  cookie = `estiva_id_session=${session.token}`
})

afterAll(async () => {
  await closePool()
})

describe('the refresh grant', () => {
  it('comes back from the code grant, so an app has one before it needs it', async () => {
    const body = await signIn(cookie)
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
  })

  it('exchanges for a usable access token without any redirect', async () => {
    const first = await signIn(cookie)
    const response = await refresh(first.refresh_token as string)
    expect(response.status).toBe(200)

    const body = (await response.json()) as TokenBody
    expect(body.access_token).toBeTruthy()
    expect(body.expires_in).toBe(600)

    /**
     * Asserting the two tokens *differ* would be testing the clock, not the
     * grant: the claims are `iss`/`sub`/`aud`/`iat`/`exp` and nothing else, so
     * two tokens minted in the same second for the same person and app are
     * byte-identical and correctly so. What matters is that the answer is a
     * well-formed token for this app with a full TTL ahead of it.
     */
    const claims = JSON.parse(
      Buffer.from((body.access_token as string).split('.')[1] as string, 'base64url').toString(),
    ) as { aud?: string; sub?: string; exp?: number }
    expect(claims.aud).toBe(CLIENT)
    expect(claims.sub).toBe(ada.pubkey)
    expect(claims.exp).toBeGreaterThan(Math.floor(Date.now() / 1000))
  })

  /**
   * Rotation. The old token is spent by the exchange, which is what makes a
   * stolen copy useless the moment the legitimate app refreshes.
   */
  it('rotates: the new token works and the old one does not', async () => {
    const first = await signIn(cookie)
    const rotated = (await (await refresh(first.refresh_token as string)).json()) as TokenBody

    expect(rotated.refresh_token).toBeTruthy()
    expect(rotated.refresh_token).not.toBe(first.refresh_token)

    expect((await refresh(rotated.refresh_token as string)).status).toBe(200)
    expect((await refresh(first.refresh_token as string)).status).toBe(400)
  })

  /**
   * Reuse detection, and the reason rotation is worth having.
   *
   * A spent token presented again means two parties hold the same credential.
   * There is no way to tell which is the thief, so the whole chain dies —
   * including the newest token, which the attacker may be the one holding.
   */
  it('burns the entire chain when a spent token is replayed', async () => {
    const first = await signIn(cookie)
    const second = (await (await refresh(first.refresh_token as string)).json()) as TokenBody
    const third = (await (await refresh(second.refresh_token as string)).json()) as TokenBody

    // The attacker replays the one they captured two rotations ago.
    expect((await refresh(first.refresh_token as string)).status).toBe(400)

    // And the legitimate app's current token is dead too. That is the point.
    expect((await refresh(third.refresh_token as string)).status).toBe(400)
  })

  it('records a replay as an error rather than an ordinary refusal', async () => {
    const first = await signIn(cookie)
    await refresh(first.refresh_token as string)
    await refresh(first.refresh_token as string)

    const rows = await query<{ outcome: string; detail: Record<string, unknown> }>(
      "select outcome, detail from audit_events where action = 'token.refresh' order by id",
    )
    const reused = rows.rows.find((r) => r.detail?.reason === 'reused')
    expect(reused?.outcome).toBe('error')
  })

  /**
   * Session binding — what makes signing out mean something (PEEK-122).
   * Without it, a refresh token would outlive the logout that was supposed to
   * end it and quietly renew a session nobody wanted.
   */
  it('stops working the moment the session is revoked', async () => {
    const first = await signIn(cookie)
    await revokeSession(sessionToken)
    expect((await refresh(first.refresh_token as string)).status).toBe(400)
  })

  it('stops working when the identity is offboarded', async () => {
    const first = await signIn(cookie)
    await setUserStatus(ada.id, 'offboarded')
    expect((await refresh(first.refresh_token as string)).status).toBe(400)
  })

  /** A token leaking to another registered app must not become a session there. */
  it('refuses a token presented by a different client', async () => {
    const first = await signIn(cookie)
    expect((await refresh(first.refresh_token as string, 'estiva-peek')).status).toBe(400)
  })

  it('refuses a token nobody issued', async () => {
    expect((await refresh(randomBytes(32).toString('base64url'))).status).toBe(400)
  })

  /**
   * A refresh token must not be a way around session lifetime, so it expires
   * with the session rather than on a clock of its own.
   */
  it('never outlives the session that justified it', async () => {
    await signIn(cookie)
    const rows = await query<{ same: boolean }>(
      `select r.expires_at = s.expires_at as same
         from refresh_tokens r join sessions s on s.id = r.session_id`,
    )
    expect(rows.rows).toHaveLength(1)
    expect(rows.rows[0]?.same).toBe(true)
  })

  it('advertises the grant in discovery', async () => {
    const response = await app.request('/.well-known/openid-configuration')
    const document = (await response.json()) as { grant_types_supported?: string[] }
    expect(document.grant_types_supported).toContain('refresh_token')
  })

  /** A malformed refresh request should not be reported as a broken code request. */
  it('names the grant it failed to parse', async () => {
    const response = await post({ grantType: 'refresh_token', clientId: CLIENT })
    expect(response.status).toBe(400)
    expect(JSON.stringify(await response.json())).toMatch(/refresh_token/)
  })
})
