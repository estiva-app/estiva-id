/**
 * PER-22 acceptance: a person's bot gets a session as them from a link they
 * approve with a passkey, everything it signs says so, and revoking it stops
 * the next request.
 *
 * The refusals are most of this file, because they are what makes the happy
 * path acceptable: only the owner can approve, only a personal bot can ask, the
 * session reaches app sign-in and nothing else, and an ended delegation cannot
 * be laundered into the person's own token.
 */
import { createHash, randomBytes } from 'node:crypto'
import { decodeJwt } from 'jose'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { findAppPolicy } from '../../domain/apps.js'
import { createInvite } from '../../domain/invites.js'
import { createOwnBot, createRoleIdentity, issueServiceCredential } from '../../domain/roles.js'
import { SoftwareAuthenticator } from '../../test/authenticator.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'
import { resetDeviceRateLimitForTests } from './device.js'

const app = createApp()
const cfg = config()

const REDIRECT = 'https://peek.test/callback'
const PEEK = 'estiva-peek'

const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: JSON.stringify(body),
  })

function sessionCookie(response: Response): string {
  const header = response.headers.get('set-cookie')
  if (!header) throw new Error('expected a session cookie')
  return header.split(';')[0] as string
}

/** A person with a passkey, enrolled the way a real one is. */
async function enrol(email: string, displayName: string) {
  const device = new SoftwareAuthenticator({
    rpId: cfg.RP_ID,
    origin: cfg.RP_ORIGINS[0] as string,
  })
  const invite = await createInvite({ email, displayName, role: 'admin', createdBy: null })
  const options = (await (
    await post('/auth/register/options', { inviteToken: invite.token })
  ).json()) as { challenge: string }
  const verified = await post('/auth/register/verify', device.register(options.challenge))
  expect(verified.status).toBe(200)
  const body = (await verified.json()) as { pubkey: string }
  const row = await query<{ id: string }>('select id from users where email = $1', [email])
  return {
    id: row.rows[0]?.id as string,
    device,
    pubkey: body.pubkey,
    cookie: sessionCookie(verified),
  }
}

async function startRequest(clientId: string, clientSecret: string) {
  const response = await post('/device/authorize', { clientId, clientSecret, label: 'test rig' })
  return {
    status: response.status,
    body: (await response.json()) as {
      device_code: string
      user_code: string
      verification_uri_complete: string
    },
  }
}

async function approve(userCode: string, device: SoftwareAuthenticator) {
  const options = (await (await post(`/device/requests/${userCode}/options`, {})).json()) as {
    challenge: string
  }
  return post(`/device/requests/${userCode}/approve`, device.authenticate(options.challenge))
}

const poll = (deviceCode: string, clientId: string, clientSecret: string) =>
  post('/device/token', { deviceCode, clientId, clientSecret })

/** The whole flow, ending with the bot holding a session cookie. */
async function delegatedCookie(bot: { clientId: string; secret: string }, owner: Person) {
  const started = await startRequest(bot.clientId, bot.secret)
  expect((await approve(started.body.user_code, owner.device)).status).toBe(200)
  // Past the polling interval, so the collect is not answered `slow_down`.
  await query(`update device_authorizations set last_polled_at = null`)
  const collected = await poll(started.body.device_code, bot.clientId, bot.secret)
  expect(collected.status).toBe(200)
  const body = (await collected.json()) as {
    session_token: string
    cookie_name: string
    delegate_tag: string
    pubkey: string
  }
  return { ...body, cookie: `${body.cookie_name}=${body.session_token}` }
}

/** What Peek does in the headless browser: `/authorize`, then the code grant. */
async function peekToken(cookie: string) {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url')
  const params = new URLSearchParams({
    client_id: PEEK,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  const authorized = await app.request(`/authorize?${params.toString()}`, { headers: { cookie } })
  const code = new URL(authorized.headers.get('location') ?? '').searchParams.get('code')
  return {
    code,
    exchange: () =>
      post('/token', {
        grantType: 'authorization_code',
        code,
        clientId: PEEK,
        redirectUri: REDIRECT,
        codeVerifier: verifier,
      }),
  }
}

type Person = Awaited<ReturnType<typeof enrol>>

let miky: Person
let bot: { clientId: string; secret: string }
let peekKind: number

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  resetDeviceRateLimitForTests()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [REDIRECT],
    PEEK,
  ])
  miky = await enrol('miky@example.test', 'Miky Example')
  bot = await createOwnBot({ ownerUserId: miky.id, label: 'Claude' })
  const policy = await findAppPolicy(PEEK)
  peekKind = policy?.allowedKinds.find((k) => ![0, 27235, 22242].includes(k)) as number
})

afterAll(async () => {
  await closePool()
})

describe('the device flow', () => {
  it('gives the bot a session as its owner, and every token from it names the bot', async () => {
    const started = await startRequest(bot.clientId, bot.secret)
    expect(started.status).toBe(200)
    expect(started.body.user_code).toMatch(/^[B-Z]{4}-[B-Z]{4}$/)
    expect(started.body.verification_uri_complete).toContain(started.body.user_code)

    // Before approval, the bot is told to keep waiting.
    const pending = await poll(started.body.device_code, bot.clientId, bot.secret)
    expect(pending.status).toBe(400)
    expect(await pending.json()).toEqual({ error: 'authorization_pending' })

    // The approval screen says who is asking and whose passkey will do.
    const shown = await app.request(`/device/requests/${started.body.user_code.toLowerCase()}`)
    expect(await shown.json()).toMatchObject({
      clientId: bot.clientId,
      ownerDisplayName: 'Miky Example',
      label: 'test rig',
    })

    expect((await approve(started.body.user_code, miky.device)).status).toBe(200)
    await query('update device_authorizations set last_polled_at = null')

    const collected = await poll(started.body.device_code, bot.clientId, bot.secret)
    expect(collected.status).toBe(200)
    const session = (await collected.json()) as {
      session_token: string
      cookie_name: string
      pubkey: string
      delegate_tag: string
    }
    expect(session.pubkey).toBe(miky.pubkey)
    expect(session.delegate_tag).toBe(`${bot.clientId}-as-miky`)

    // Collected once. A second collect is not a second session.
    await query('update device_authorizations set last_polled_at = null')
    const again = await poll(started.body.device_code, bot.clientId, bot.secret)
    expect(await again.json()).toEqual({ error: 'invalid_grant' })

    const cookie = `${session.cookie_name}=${session.session_token}`
    const me = await app.request('/me', { headers: { cookie } })
    expect(await me.json()).toMatchObject({
      pubkey: miky.pubkey,
      delegate: { clientId: bot.clientId },
    })

    const { exchange } = await peekToken(cookie)
    const token = (await (await exchange()).json()) as {
      access_token: string
      refresh_token: string
      expires_in: number
    }
    const claims = decodeJwt(token.access_token)
    expect(claims.sub).toBe(miky.pubkey)
    expect(claims.act).toEqual({ sub: bot.clientId })
    expect(token.expires_in).toBe(cfg.DELEGATED_JWT_TTL_SECONDS)

    // The refresh grant keeps naming the bot.
    const refreshed = (await (
      await post('/token', {
        grantType: 'refresh_token',
        refreshToken: token.refresh_token,
        clientId: PEEK,
      })
    ).json()) as { access_token: string }
    expect(decodeJwt(refreshed.access_token).act).toEqual({ sub: bot.clientId })
  })

  it('signs as the person with the bot tag, audits it, and stops on revoke', async () => {
    const delegated = await delegatedCookie(bot, miky)
    const token = (await (await (await peekToken(delegated.cookie)).exchange()).json()) as {
      access_token: string
    }
    const bearer = { authorization: `Bearer ${token.access_token}` }

    const signed = await post(
      '/sign',
      { event: { kind: peekKind, tags: [['client', 'peek']], content: 'hello' } },
      bearer,
    )
    expect(signed.status).toBe(200)
    const { event } = (await signed.json()) as {
      event: { pubkey: string; tags: string[][]; id: string }
    }
    expect(event.pubkey).toBe(miky.pubkey)
    // The app's own client tag is replaced, not joined.
    expect(event.tags.filter((t) => t[0] === 'client')).toEqual([
      ['client', `${bot.clientId}-as-miky`],
    ])

    const audit = await query<{ detail: Record<string, unknown> }>(
      `select detail from audit_events where action = 'sign.granted' and detail->>'eventId' = $1`,
      [event.id],
    )
    expect(audit.rows[0]?.detail).toMatchObject({ delegate: bot.clientId })

    // Revoke from the account page, with the person's own session.
    const listed = (await (
      await app.request('/me/delegations', { headers: { cookie: miky.cookie } })
    ).json()) as { delegations: { id: string }[] }
    expect(listed.delegations).toHaveLength(1)
    const revoked = await post(
      `/me/delegations/${listed.delegations[0]?.id}/revoke`,
      {},
      { cookie: miky.cookie },
    )
    expect(revoked.status).toBe(200)

    // The very next request, with a token that has not expired.
    const after = await post('/sign', { event: { kind: peekKind, content: 'again' } }, bearer)
    expect(after.status).toBe(401)
    const nip44 = await post('/nip44/encrypt', { plaintext: 'x' }, bearer)
    expect(nip44.status).toBe(401)
  })

  it('does not let an ended delegation become the person’s own token', async () => {
    const delegated = await delegatedCookie(bot, miky)
    const { exchange } = await peekToken(delegated.cookie)
    await query('update sessions set revoked_at = now() where delegate_client_id is not null')
    const response = await exchange()
    expect(response.status).toBe(400)
  })

  it('reaches app sign-in only — not the account or admin surface', async () => {
    const { cookie } = await delegatedCookie(bot, miky)
    for (const path of ['/me/profile', '/me/credentials', '/me/delegations', '/admin/people']) {
      const response = await app.request(path, { headers: { cookie } })
      expect(response.status, path).toBe(403)
    }
    const bots = await post('/me/bots', { label: 'another' }, { cookie })
    expect(bots.status).toBe(403)
  })
})

describe('who may ask, and who may approve', () => {
  it('refuses an approval by anybody but the bot’s owner', async () => {
    const colleague = await enrol('ada@example.test', 'Ada')
    const started = await startRequest(bot.clientId, bot.secret)
    const response = await approve(started.body.user_code, colleague.device)
    expect(response.status).toBe(403)

    await query('update device_authorizations set last_polled_at = null')
    const polled = await poll(started.body.device_code, bot.clientId, bot.secret)
    expect(await polled.json()).toEqual({ error: 'authorization_pending' })
  })

  it('refuses a workspace role, which has nobody to act as', async () => {
    const role = await createRoleIdentity({ displayName: 'Relay Operator' })
    const credential = await issueServiceCredential({
      userId: role.id,
      clientId: 'relay-operator',
      name: 'Relay Operator',
      allowedKinds: [],
    })
    const started = await startRequest(credential.clientId, credential.secret)
    expect(started.status).toBe(401)
  })

  it('refuses a wrong secret, to ask and to collect', async () => {
    expect((await startRequest(bot.clientId, 'wrong')).status).toBe(401)
    const started = await startRequest(bot.clientId, bot.secret)
    expect((await poll(started.body.device_code, bot.clientId, 'wrong')).status).toBe(401)
  })

  it('stops a denied request', async () => {
    const started = await startRequest(bot.clientId, bot.secret)
    expect((await post(`/device/requests/${started.body.user_code}/deny`, {})).status).toBe(200)
    const polled = await poll(started.body.device_code, bot.clientId, bot.secret)
    expect(await polled.json()).toEqual({ error: 'access_denied' })
  })

  it('tells a bot polling too fast to slow down', async () => {
    const started = await startRequest(bot.clientId, bot.secret)
    await poll(started.body.device_code, bot.clientId, bot.secret)
    const second = await poll(started.body.device_code, bot.clientId, bot.secret)
    expect(await second.json()).toEqual({ error: 'slow_down' })
  })
})
