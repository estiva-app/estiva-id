/**
 * `POST /timing`: what reaches Sentry is read off the envelope this server
 * sends, so a field that leaks anywhere on the way fails here.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigForTests } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const ORIGIN = 'http://localhost:5191'
const TIMINGS_DSN = 'https://tim456@o1.ingest.de.sentry.io/77'
const ERRORS_DSN = 'https://abc123@o1.ingest.de.sentry.io/42'
const CHROME =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'
const PLANTED_TITLE = 'plantedtitle board offsite'
const PLANTED_ADDRESS = 'plantedaddress-5a1c9e'

let app: ReturnType<typeof createApp>
let personToken: string
let personPubkey: string
let qaToken: string
let sentry: ReturnType<typeof vi.fn>
let clock = Date.now()

const timing = () => ({
  release: 'ded93b9c',
  screen: 'issue',
  how: 'new-tab',
  waitMs: 2400,
  ready: 'placeholder-gone',
})

function send(token: string | undefined, body: unknown, headers: Record<string, string> = {}) {
  return app.request('/timing', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      'user-agent': CHROME,
      'x-forwarded-for': '203.0.113.7',
      'cf-connecting-ip': '203.0.113.7',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

const sentCalls = () =>
  sentry.mock.calls.map((call) => ({
    url: String(call[0]),
    body: String((call[1] as RequestInit).body),
  }))
const sentEvent = () => JSON.parse(sentCalls()[0]?.body.split('\n')[2] ?? 'null')

beforeAll(async () => {
  process.env.SENTRY_DSNS = `estiva-ship=${ERRORS_DSN},estiva-peek=${ERRORS_DSN}`
  process.env.TIMINGS_DSNS = `estiva-ship=${TIMINGS_DSN}`
  resetConfigForTests()
  await prepareDatabase()
  app = createApp()
})

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ['Date'] })
  clock += 2 * 60 * 60_000
  vi.setSystemTime(clock)
  await truncateAll()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [`${ORIGIN}/auth/callback`],
    'estiva-ship',
  ])
  const ada = await createUserWithKey({ email: 'ada@example.test' })
  personPubkey = ada.pubkey
  personToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-ship' })).token
  const qa = await createUserWithKey({ email: 'qa-1@example.test', testAccount: true })
  qaToken = (await issueToken({ pubkey: qa.pubkey, clientId: 'estiva-ship' })).token
  sentry = vi.fn(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', sentry)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

afterAll(async () => {
  process.env.SENTRY_DSNS = ''
  process.env.TIMINGS_DSNS = ''
  resetConfigForTests()
  await closePool()
})

describe('POST /timing', () => {
  it('refuses a timing without a sign-in, and sends nothing to Sentry', async () => {
    const response = await send(undefined, timing())
    expect(response.status).toBe(401)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('refuses a timing with a token that is not ours', async () => {
    const response = await send('not.a.token', timing())
    expect(response.status).toBe(401)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('sends Sentry a transaction as long as the wait, named by kind of screen, how it was opened and who', async () => {
    const response = await send(personToken, timing())
    expect(response.status).toBe(202)
    expect(await response.json()).toEqual({ sent: true })
    const [call] = sentCalls()
    expect(call?.url).toBe('https://o1.ingest.de.sentry.io/api/77/envelope/')
    expect(call?.body.split('\n')[1]).toBe('{"type":"transaction"}')
    const event = sentEvent()
    expect(event.type).toBe('transaction')
    expect(event.transaction).toBe('open issue')
    expect(Math.round((event.timestamp - event.start_timestamp) * 1000)).toBe(2400)
    expect(event.release).toBe('ded93b9c')
    expect(event.user).toEqual({ id: personPubkey })
    expect(event.tags).toEqual({
      app: 'estiva-ship',
      account: 'person',
      screen: 'issue',
      how: 'new-tab',
      ready: 'placeholder-gone',
      browser: 'Chrome',
    })
  })

  it('sends when Peek’s saved picture showed as a second number beside the wait, never as the wait', async () => {
    await send(personToken, { ...timing(), waitMs: 2400, pictureMs: 180 })
    const event = sentEvent()
    expect(Math.round((event.timestamp - event.start_timestamp) * 1000)).toBe(2400)
    expect(event.measurements).toEqual({ picture: { value: 180, unit: 'millisecond' } })
  })

  it('leaves out a picture number that is not one of ours, and still sends the wait', async () => {
    for (const pictureMs of [-1, 1.5, 2401, 3_600_000, '180', { value: 'plantedtitle' }]) {
      sentry.mockClear()
      expect((await send(personToken, { ...timing(), pictureMs })).status).toBe(202)
      const event = sentEvent()
      expect(event.measurements).toBeUndefined()
      expect(sentCalls()[0]?.body).not.toContain('plantedtitle')
    }
  })

  it('sends no picture number when the browser sent none', async () => {
    await send(personToken, timing())
    expect(sentEvent().measurements).toBeUndefined()
  })

  it('sends an open the person left while it was loading, marked left', async () => {
    await send(personToken, { ...timing(), waitMs: 4000, ready: 'left' })
    expect(sentEvent().tags.ready).toBe('left')
  })

  it('marks a QA account as QA', async () => {
    await send(qaToken, timing())
    expect(sentEvent().tags.account).toBe('qa')
  })

  it('sends no address, title, IP address or field off the list, whatever the browser sent', async () => {
    await send(personToken, {
      ...timing(),
      screen: `/issue/${PLANTED_ADDRESS}`,
      title: PLANTED_TITLE,
      url: `${ORIGIN}/issue/${PLANTED_ADDRESS}`,
      user: { ip_address: '203.0.113.7', email: 'ada@example.test' },
      pubkey: 'f'.repeat(64),
    })
    const envelope = sentCalls()[0]?.body ?? ''
    for (const planted of [
      'plantedtitle',
      'offsite',
      'plantedaddress',
      '203.0.113.7',
      'ip_address',
      'example.test',
      'f'.repeat(64),
    ])
      expect(envelope).not.toContain(planted)
    expect(sentEvent().tags.screen).toBe('<unknown>')
  })

  it('refuses a body that is not a timing, and sends nothing', async () => {
    for (const body of [
      'not json',
      { ...timing(), how: 'teleport' },
      { ...timing(), ready: 'whenever' },
      { ...timing(), waitMs: -1 },
      { ...timing(), waitMs: 1.5 },
      { ...timing(), waitMs: 3_600_000 },
      { ...timing(), waitMs: '2400' },
    ]) {
      expect((await send(personToken, body)).status).toBe(400)
    }
    expect(sentry).not.toHaveBeenCalled()
  })

  it('accepts and drops a timing from an app with an errors address but none for timings', async () => {
    await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
      [`${ORIGIN}/auth/callback`],
      'estiva-peek',
    ])
    const ada = await createUserWithKey({ email: 'peek-user@example.test' })
    const peekToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
    const response = await send(peekToken, { ...timing(), screen: '/app/desk' })
    expect(response.status).toBe(202)
    expect(await response.json()).toEqual({ sent: false, reason: 'not_collected' })
    expect(sentry).not.toHaveBeenCalled()
  })

  it('spends no budget on a body that is not a timing', async () => {
    for (let i = 0; i < 300; i++) await send(personToken, { ...timing(), how: 'teleport' })
    expect((await send(personToken, timing())).status).toBe(202)
  })

  it('stops one person at 300 timings an hour', async () => {
    for (let i = 0; i < 300; i++) expect((await send(personToken, timing())).status).toBe(202)
    const response = await send(personToken, timing())
    expect(response.status).toBe(429)
    expect(sentry).toHaveBeenCalledTimes(300)
  })

  it('stops an app at 1,000 timings an hour across everyone, so Sentry’s month cannot be used up', async () => {
    const tokens: string[] = []
    for (let i = 0; i < 4; i++) {
      const user = await createUserWithKey({ email: `many-${i}@example.test` })
      tokens.push((await issueToken({ pubkey: user.pubkey, clientId: 'estiva-ship' })).token)
    }
    for (const token of tokens)
      for (let i = 0; i < 250; i++) expect((await send(token, timing())).status).toBe(202)
    const ada = await send(personToken, timing())
    expect(ada.status).toBe(429)
    expect(sentry).toHaveBeenCalledTimes(1000)
  })

  it('counts timings apart from error reports, so a day of opens never crowds out a crash', async () => {
    for (let i = 0; i < 300; i++) await send(personToken, timing())
    expect((await send(personToken, timing())).status).toBe(429)
    const crash = await app.request('/report', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: ORIGIN,
        'user-agent': CHROME,
        authorization: `Bearer ${personToken}`,
      },
      body: JSON.stringify({
        release: 'ded93b9c',
        how: 'boundary',
        error: { type: 'TypeError', message: 'x is undefined', frames: [] },
        screen: 'issue',
        trail: [],
      }),
    })
    expect(crash.status).toBe(202)
    expect(await crash.json()).toEqual({ sent: true })
  })

  it('answers a preflight from a registered app', async () => {
    const response = await app.request('/timing', {
      method: 'OPTIONS',
      headers: { origin: ORIGIN, 'access-control-request-method': 'POST' },
    })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
  })
})
