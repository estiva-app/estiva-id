/**
 * `/token` in the standard OAuth format (record sign-in-is-plain-oauth).
 *
 * What any OAuth library sends: an `application/x-www-form-urlencoded` body
 * with RFC 6749's parameter names, answered with RFC 6749 §5.2 errors. A
 * standard client signs in with a code and PKCE, renews with the refresh
 * token, and a refused renewal gets `invalid_grant` rather than this service's
 * own error shape.
 */
import { createHash, randomBytes } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createRoleIdentity, issueServiceCredential } from '../../domain/roles.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

const REDIRECT = 'https://ship.test/callback'
const CLIENT = 'estiva-ship'

const form = (params: Record<string, string> | string, headers: Record<string, string> = {}) =>
  app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: typeof params === 'string' ? params : new URLSearchParams(params).toString(),
  })

interface TokenBody {
  access_token?: string
  refresh_token?: string
  token_type?: string
  expires_in?: number
  pubkey?: string
  error?: string
  error_description?: string
}

let ada: Awaited<ReturnType<typeof createUserWithKey>>
let cookie: string

/**
 * The browser half, then the code redeemed in the form format — with a
 * different verifier than the one the challenge was made from, if given.
 */
async function signIn(presentedVerifier?: string): Promise<Response> {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url')
  const params = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  const authorized = await app.request(`/authorize?${params.toString()}`, { headers: { cookie } })
  const code = new URL(authorized.headers.get('location') ?? '').searchParams.get('code') ?? ''
  return form({
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT,
    code_verifier: presentedVerifier ?? verifier,
    client_id: CLIENT,
  })
}

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
  cookie = `estiva_id_session=${session.token}`
})

afterAll(async () => {
  await closePool()
})

describe('a standard OAuth client', () => {
  it('signs in with a code and PKCE, and the answer is never cached', async () => {
    const response = await signIn()
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toBe('no-store')

    const body = (await response.json()) as TokenBody
    expect(body.token_type).toBe('Bearer')
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).toBeTruthy()
    expect(body.pubkey).toBe(ada.pubkey)
  })

  it('renews with the refresh token', async () => {
    const first = (await (await signIn()).json()) as TokenBody
    const response = await form({
      grant_type: 'refresh_token',
      refresh_token: first.refresh_token as string,
      client_id: CLIENT,
    })
    expect(response.status).toBe(200)
    const body = (await response.json()) as TokenBody
    expect(body.access_token).toBeTruthy()
    expect(body.refresh_token).not.toBe(first.refresh_token)
  })

  it('gets invalid_grant for a refresh token nobody issued', async () => {
    const response = await form({
      grant_type: 'refresh_token',
      refresh_token: randomBytes(32).toString('base64url'),
      client_id: CLIENT,
    })
    expect(response.status).toBe(400)
    expect(await response.json()).toEqual({ error: 'invalid_grant' })
  })

  it('gets invalid_grant renewing for a person who has been offboarded', async () => {
    const first = (await (await signIn()).json()) as TokenBody
    await setUserStatus(ada.id, 'offboarded')
    const response = await form({
      grant_type: 'refresh_token',
      refresh_token: first.refresh_token as string,
      client_id: CLIENT,
    })
    expect(response.status).toBe(400)
    expect(((await response.json()) as TokenBody).error).toBe('invalid_grant')
  })

  it('gets invalid_client renewing for an app that has been disabled', async () => {
    const first = (await (await signIn()).json()) as TokenBody
    await query("update app_credentials set status = 'disabled' where client_id = $1", [CLIENT])
    const response = await form({
      grant_type: 'refresh_token',
      refresh_token: first.refresh_token as string,
      client_id: CLIENT,
    })
    expect(response.status).toBe(401)
    expect(((await response.json()) as TokenBody).error).toBe('invalid_client')
  })

  it('gets invalid_grant for a code with the wrong verifier', async () => {
    const response = await signIn(randomBytes(32).toString('base64url'))
    expect(response.status).toBe(400)
    expect(((await response.json()) as TokenBody).error).toBe('invalid_grant')
  })
})

describe('a malformed form request', () => {
  it('without grant_type is invalid_request, even with a session cookie', async () => {
    const response = await form({ client_id: CLIENT }, { cookie })
    expect(response.status).toBe(400)
    const body = (await response.json()) as TokenBody
    expect(body.error).toBe('invalid_request')
    expect(body.access_token).toBeUndefined()
  })

  it('names the missing parameter in its own spelling', async () => {
    const response = await form({ grant_type: 'refresh_token', client_id: CLIENT })
    expect(response.status).toBe(400)
    const body = (await response.json()) as TokenBody
    expect(body.error).toBe('invalid_request')
    expect(body.error_description).toMatch(/refresh_token/)
  })

  it('treats a parameter with no value as missing', async () => {
    const response = await form({
      grant_type: 'refresh_token',
      refresh_token: '',
      client_id: CLIENT,
    })
    expect(((await response.json()) as TokenBody).error).toBe('invalid_request')
  })

  it('refuses a parameter sent twice', async () => {
    const response = await form(
      `grant_type=refresh_token&refresh_token=a&refresh_token=b&client_id=${CLIENT}`,
    )
    expect(response.status).toBe(400)
    expect(((await response.json()) as TokenBody).error).toBe('invalid_request')
  })

  it('answers unsupported_grant_type for a grant this service does not offer', async () => {
    const response = await form({ grant_type: 'password', client_id: CLIENT })
    expect(response.status).toBe(400)
    expect(((await response.json()) as TokenBody).error).toBe('unsupported_grant_type')
  })
})

describe('a bot in the form format', () => {
  it('signs in with its secret in the body, and a wrong secret is invalid_client', async () => {
    const bot = await createRoleIdentity({ displayName: 'Form Bot' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'form-bot',
      name: 'Form Bot',
      allowedKinds: [9],
    })

    const good = await form({
      grant_type: 'client_credentials',
      client_id: credential.clientId,
      client_secret: credential.secret,
    })
    expect(good.status).toBe(200)
    expect(((await good.json()) as TokenBody).pubkey).toBe(bot.pubkey)

    const wrong = await form({
      grant_type: 'client_credentials',
      client_id: credential.clientId,
      client_secret: 'not-the-secret',
    })
    expect(wrong.status).toBe(401)
    expect(await wrong.json()).toEqual({ error: 'invalid_client' })
  })

  /** What most OAuth libraries send by default for a client holding a secret. */
  it('signs in with its secret in HTTP Basic, and two methods at once are refused', async () => {
    const bot = await createRoleIdentity({ displayName: 'Basic Bot' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'basic-bot',
      name: 'Basic Bot',
      allowedKinds: [9],
    })
    const basic = `Basic ${Buffer.from(
      `${encodeURIComponent(credential.clientId)}:${encodeURIComponent(credential.secret)}`,
    ).toString('base64')}`

    const good = await form({ grant_type: 'client_credentials' }, { authorization: basic })
    expect(good.status).toBe(200)
    expect(((await good.json()) as TokenBody).pubkey).toBe(bot.pubkey)

    const both = await form(
      { grant_type: 'client_credentials', client_secret: credential.secret },
      { authorization: basic },
    )
    expect(both.status).toBe(400)
    expect(((await both.json()) as TokenBody).error).toBe('invalid_request')
  })
})
