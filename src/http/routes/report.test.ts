/**
 * `POST /report`: what reaches Sentry is read off the envelope this server
 * sends, not off the report object, so a field that leaks anywhere on the way
 * fails here.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigForTests } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { SESSION_COOKIE, createSession } from '../../domain/sessions.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const ORIGIN = 'http://localhost:5190'
const DSN = 'https://abc123@o1.ingest.de.sentry.io/42'
const CHROME =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'

// Text a person wrote, as it can turn up inside an error.
const PLANTED_MESSAGE = 'plantedmessage quarterly numbers'
const PLANTED_TITLE = 'plantedtitle board offsite'
const PLANTED_ADDRESS = 'plantedaddress-5a1c9e'

let app: ReturnType<typeof createApp>
let personToken: string
let personPubkey: string
let qaToken: string
let sentry: ReturnType<typeof vi.fn>

function report(token: string | undefined, body: unknown, headers: Record<string, string> = {}) {
  return app.request('/report', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      'user-agent': CHROME,
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  })
}

/** Every envelope sent to Sentry, as the text that went on the wire. */
const sentEnvelopes = () => sentry.mock.calls.map((call) => String((call[1] as RequestInit).body))
const sentEvent = () => JSON.parse(sentEnvelopes()[0]?.split('\n')[2] ?? 'null')

/**
 * The rate limits keep their windows in process memory, so each test runs two
 * hours after the last on a fake clock: no test spends another's budget.
 */
let clock = Date.now()

const makeCrash = () => ({
  release: 'ded93b9c',
  how: 'boundary',
  error: {
    type: 'SyntaxError',
    message: `Unexpected token 'p', "${PLANTED_MESSAGE}" is not valid JSON`,
    frames: [
      { function: 'parseBody', file: `${ORIGIN}/assets/index-Ab12.js`, line: 1, column: 4567 },
      { function: 'render', file: `${ORIGIN}/app/teams/${PLANTED_ADDRESS}`, line: 3, column: 9 },
      { function: 'plantedmessage quarterly numbers', file: `${ORIGIN}/assets/index-Ab12.js` },
      { function: 'inject', file: 'https://elsewhere.example/assets/x.js', line: 1, column: 1 },
    ],
  },
  screen: '/app/teams/:id',
  trail: [
    { at: Date.now() - 5_000, screen: '/app/desk' },
    { at: Date.now() - 4_000, screen: `/t/${PLANTED_ADDRESS}` },
    { at: Date.now() - 3_000, action: 'sent-message' },
    { at: Date.now() - 2_000, action: PLANTED_TITLE.replaceAll(' ', '-') },
    { at: Date.now() - 1_000, screen: '/search/plantedtitle/board' },
  ],
  // Fields outside the list, as a careless or older reporter might send them.
  pubkey: 'f'.repeat(64),
  url: `${ORIGIN}/app/teams/${PLANTED_ADDRESS}`,
  title: PLANTED_TITLE,
  user: { ip_address: '203.0.113.7', email: 'ada@example.test' },
  request: { url: `${ORIGIN}/t/${PLANTED_ADDRESS}` },
})
let crash: ReturnType<typeof makeCrash>

beforeAll(async () => {
  process.env.SENTRY_DSNS = `estiva-peek=${DSN},estiva-leaf=${DSN},estiva-id-web=${DSN}`
  resetConfigForTests()
  await prepareDatabase()
  app = createApp()
})

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ['Date'] })
  clock += 2 * 60 * 60_000
  vi.setSystemTime(clock)
  crash = makeCrash()
  await truncateAll()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [`${ORIGIN}/auth/callback`],
    'estiva-peek',
  ])
  const ada = await createUserWithKey({ email: 'ada@example.test' })
  personPubkey = ada.pubkey
  personToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
  const qa = await createUserWithKey({ email: 'qa-1@example.test', testAccount: true })
  qaToken = (await issueToken({ pubkey: qa.pubkey, clientId: 'estiva-peek' })).token
  sentry = vi.fn(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', sentry)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

afterAll(async () => {
  process.env.SENTRY_DSNS = ''
  resetConfigForTests()
  await closePool()
})

describe('POST /report', () => {
  it('refuses a report without a sign-in, and sends nothing to Sentry', async () => {
    const response = await report(undefined, crash)
    expect(response.status).toBe(401)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('refuses a report with a token that is not ours', async () => {
    const response = await report('not.a.token', crash)
    expect(response.status).toBe(401)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('sends Sentry no planted message text, title or page address', async () => {
    const response = await report(personToken, crash)
    expect(response.status).toBe(202)
    expect(await response.json()).toEqual({ sent: true })

    const [envelope] = sentEnvelopes()
    expect(envelope).toBeDefined()
    for (const planted of [
      'plantedmessage',
      'quarterly',
      'plantedtitle',
      'offsite',
      'plantedaddress',
    ]) {
      expect(envelope).not.toContain(planted)
    }
  })

  it('sends Sentry only the listed fields, with no IP address, email or request', async () => {
    await report(personToken, crash)
    const envelope = sentEnvelopes()[0] as string
    expect(envelope).not.toContain('203.0.113.7')
    expect(envelope).not.toContain('ip_address')
    expect(envelope).not.toContain('example.test')

    const event = sentEvent()
    expect(Object.keys(event).sort()).toEqual(
      [
        'breadcrumbs',
        'contexts',
        'environment',
        'event_id',
        'exception',
        'level',
        'platform',
        'release',
        'tags',
        'timestamp',
        'transaction',
        'user',
      ].sort(),
    )
    expect(event.user).toEqual({ id: personPubkey })
    expect(event.tags).toEqual({ app: 'estiva-peek', account: 'person', screen: '/app/teams/:id' })
    expect(event.contexts).toEqual({ browser: { name: 'Chrome', version: '131' } })
  })

  it('sends a failure the person was told about under our fixed sentence, grouped by its name, and nothing planted', async () => {
    const response = await report(qaToken, {
      ...crash,
      how: 'failure',
      named: 'not-sent',
      error: {
        type: 'Failure',
        message: `Not sent in ${PLANTED_TITLE}`,
        frames: crash.error.frames,
      },
    })
    expect(response.status).toBe(202)
    const envelope = sentEnvelopes()[0] as string
    for (const planted of ['plantedmessage', 'plantedtitle', 'plantedaddress']) {
      expect(envelope).not.toContain(planted)
    }
    const event = sentEvent()
    expect(event.exception.values[0]).toMatchObject({
      type: 'Failure',
      value: 'Not sent',
      mechanism: { type: 'failure-shown', handled: true },
      stacktrace: { frames: [] },
    })
    expect(event.fingerprint).toEqual(['failure', 'not-sent'])
    expect(event.tags).toMatchObject({ account: 'qa', failure: 'not-sent' })
  })

  it('sends a failure named outside the list as unnamed', async () => {
    await report(personToken, { ...crash, how: 'failure', named: PLANTED_TITLE })
    const event = sentEvent()
    expect(event.exception.values[0].value).toBe('A failure the app showed')
    // Grouped by screen too, so one app's unnamed failures are not one row.
    expect(event.fingerprint).toEqual(['failure', 'unnamed', '/app/teams/:id'])
    expect(sentEnvelopes()[0]).not.toContain('plantedtitle')
  })

  it("sends a refused write by its code alone, never the relay's sentence", async () => {
    await report(personToken, {
      ...crash,
      how: 'refused',
      named: 'archived',
      error: {
        type: 'WriteRefused',
        message: `invalid: archived: team “${PLANTED_TITLE}” is archived`,
        frames: [],
      },
    })
    const event = sentEvent()
    expect(event.exception.values[0]).toMatchObject({
      type: 'WriteRefused',
      value: 'archived',
      mechanism: { type: 'write-refused', handled: true },
    })
    expect(event.fingerprint).toEqual(['refused', 'archived'])
    expect(event.tags).toMatchObject({ code: 'archived' })
    expect(sentEnvelopes()[0]).not.toContain('plantedtitle')
  })

  it('sends a refusal code of any other shape as uncoded', async () => {
    await report(personToken, { ...crash, how: 'refused', named: `blocked: ${PLANTED_TITLE}` })
    expect(sentEvent().fingerprint).toEqual(['refused', 'uncoded'])
  })

  it('takes who sent it from the sign-in, never from the report', async () => {
    await report(personToken, crash)
    expect(sentEvent().user.id).toBe(personPubkey)
    expect(sentEnvelopes()[0]).not.toContain('f'.repeat(64))
  })

  it('marks a QA account as QA', async () => {
    await report(qaToken, crash)
    expect(sentEvent().tags.account).toBe('qa')
  })

  it("keeps a frame's place in the app's own bundle and drops any other address", async () => {
    await report(personToken, crash)
    const exception = sentEvent().exception.values[0]
    expect(exception.type).toBe('SyntaxError')
    expect(exception.value).toBe('Unexpected token … is not valid JSON')
    expect(exception.mechanism).toEqual({ type: 'react.errorboundary', handled: false })
    // Oldest call first, as Sentry reads them.
    // A frame outside our bundles keeps no name, and a name that is not code is dropped.
    expect(exception.stacktrace.frames).toEqual([
      { abs_path: '<other>', filename: '<other>', in_app: false },
      {
        abs_path: `${ORIGIN}/assets/index-Ab12.js`,
        filename: `${ORIGIN}/assets/index-Ab12.js`,
        in_app: true,
      },
      { abs_path: '<other>', filename: '<other>', in_app: false },
      {
        function: 'parseBody',
        abs_path: `${ORIGIN}/assets/index-Ab12.js`,
        filename: `${ORIGIN}/assets/index-Ab12.js`,
        lineno: 1,
        colno: 4567,
        in_app: true,
      },
    ])
  })

  it('keeps the steps before the error that are screens and named actions', async () => {
    await report(personToken, crash)
    const steps = sentEvent().breadcrumbs.values.map((step: { message: string }) => step.message)
    expect(steps).toEqual(['opened /app/desk', 'sent-message'])
  })

  it('sends a screen as <unknown> when it is not one of the app’s routes', async () => {
    await report(personToken, { ...crash, screen: '/search/plantedtitle/board' })
    expect(sentEvent().tags.screen).toBe('<unknown>')
    expect(sentEnvelopes()[0]).not.toContain('plantedtitle')
  })

  it('sends the same release it was given, so Sentry can tell versions apart', async () => {
    await report(personToken, crash)
    expect(sentEvent().release).toBe('ded93b9c')
  })

  it('posts to the envelope endpoint the DSN names, with its key', async () => {
    await report(personToken, crash)
    const [url, init] = sentry.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('https://o1.ingest.de.sentry.io/api/42/envelope/')
    expect((init.headers as Record<string, string>)['x-sentry-auth']).toContain('sentry_key=abc123')
  })

  it('stops one person at 30 reports in ten minutes', async () => {
    for (let i = 0; i < 30; i++) {
      expect((await report(personToken, crash)).status).toBe(202)
    }
    const refused = await report(personToken, crash)
    expect(refused.status).toBe(429)
    expect(sentry).toHaveBeenCalledTimes(30)
  })

  it('stops an app at 100 reports an hour, across everyone', async () => {
    const tokens = await Promise.all(
      [1, 2, 3, 4].map(async (n) => {
        const { pubkey } = await createUserWithKey({ email: `p${n}@example.test` })
        return (await issueToken({ pubkey, clientId: 'estiva-peek' })).token
      }),
    )
    const statuses: number[] = []
    for (const token of tokens) {
      for (let i = 0; i < 26; i++) statuses.push((await report(token, crash)).status)
    }
    expect(statuses.filter((s) => s === 202)).toHaveLength(100)
    expect(statuses.slice(100)).toEqual([429, 429, 429, 429])
    expect(sentry).toHaveBeenCalledTimes(100)
  })

  it('accepts and drops a report from an app with no Sentry address', async () => {
    const pubkey = (await createUserWithKey({ email: 'bo@example.test' })).pubkey
    const shipToken = (await issueToken({ pubkey, clientId: 'estiva-ship' })).token
    const response = await report(shipToken, crash)
    expect(response.status).toBe(202)
    expect(await response.json()).toEqual({ sent: false, reason: 'not_collected' })
    expect(sentry).not.toHaveBeenCalled()
  })

  it('refuses a body that is not a report', async () => {
    expect((await report(personToken, 'not json')).status).toBe(400)
    expect((await report(personToken, 'x'.repeat(40_000))).status).toBe(400)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('answers a preflight from a registered app', async () => {
    const response = await app.request('/report', {
      method: 'OPTIONS',
      headers: { origin: ORIGIN, 'access-control-request-method': 'POST' },
    })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
  })

  it("keeps Leaf's page name as the screen, and sends a document's address as <unknown>", async () => {
    const { pubkey } = await createUserWithKey({ email: 'cy@example.test' })
    const leafToken = (await issueToken({ pubkey, clientId: 'estiva-leaf' })).token
    await report(leafToken, {
      ...crash,
      screen: 'document',
      trail: [
        { at: Date.now() - 2_000, screen: 'home' },
        { at: Date.now() - 1_000, screen: `/document/${PLANTED_ADDRESS}` },
      ],
    })
    const event = sentEvent()
    expect(event.tags).toMatchObject({ app: 'estiva-leaf', screen: 'document' })
    expect(event.breadcrumbs.values.map((b: { message: string }) => b.message)).toEqual([
      'opened home',
    ])
    expect(sentEnvelopes()[0]).not.toContain('plantedaddress')
  })
})

/** Estiva ID's own pages (PROD-4): no token; the session cookie, or the door before sign-in. */
describe("POST /report from Estiva ID's own pages", () => {
  const OWN = 'http://localhost:8787'
  const ownCrash = () => ({
    ...crash,
    screen: '/',
    trail: [{ at: Date.now() - 1_000, screen: '/' }],
    error: {
      ...crash.error,
      frames: [{ function: 'SignIn', file: `${OWN}/assets/index-Cd34.js`, line: 1, column: 99 }],
    },
  })
  const fromOwnPage = (headers: Record<string, string> = {}) =>
    report(undefined, ownCrash(), { origin: OWN, ...headers })

  // The door's day is longer than the two hours between tests: each of these starts a day later.
  beforeEach(() => {
    clock += 25 * 60 * 60_000
    vi.setSystemTime(clock)
  })

  it('takes a crash before sign-in, marked as not signed in and with no public key', async () => {
    const response = await fromOwnPage()
    expect(response.status).toBe(202)
    const event = sentEvent()
    expect(event.tags).toMatchObject({ app: 'estiva-id-web', account: 'signed-out', screen: '/' })
    expect(event.user).toBeUndefined()
    expect(event.exception.values[0].stacktrace.frames[0].abs_path).toBe(
      `${OWN}/assets/index-Cd34.js`,
    )
    expect(sentEnvelopes()[0]).not.toContain('plantedmessage')
  })

  it('says who it is when the page is signed in, by its session cookie', async () => {
    const ada = await createUserWithKey({ email: 'ada2@example.test' })
    const { token } = await createSession({ userId: ada.id })
    expect((await fromOwnPage({ cookie: `${SESSION_COOKIE}=${token}` })).status).toBe(202)
    const event = sentEvent()
    expect(event.user).toEqual({ id: ada.pubkey })
    expect(event.tags).toMatchObject({ app: 'estiva-id-web', account: 'person' })
  })

  it('refuses a report with no sign-in from any other page', async () => {
    const response = await report(undefined, ownCrash(), { origin: 'https://elsewhere.example' })
    expect(response.status).toBe(401)
    const noOrigin = await app.request('/report', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(ownCrash()),
    })
    expect(noOrigin.status).toBe(401)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('does not keep the session alive: reporting is not a use of it', async () => {
    const ada = await createUserWithKey({ email: 'ada3@example.test' })
    const { id, token } = await createSession({ userId: ada.id })
    const idleEnd = async () =>
      (await query<{ t: Date }>('select idle_expires_at as t from sessions where id = $1', [id]))
        .rows[0]?.t
    const before = await idleEnd()
    clock += 60 * 60_000
    vi.setSystemTime(clock)
    expect((await fromOwnPage({ cookie: `${SESSION_COOKIE}=${token}` })).status).toBe(202)
    expect(sentEvent().user).toEqual({ id: ada.pubkey })
    expect(await idleEnd()).toEqual(before)
  })

  it('refuses a signed-in page whose person has no active key', async () => {
    const ada = await createUserWithKey({ email: 'ada4@example.test' })
    const { token } = await createSession({ userId: ada.id })
    await query("update user_keys set status = 'revoked' where user_id = $1", [ada.id])
    const response = await fromOwnPage({ cookie: `${SESSION_COOKIE}=${token}` })
    expect(response.status).toBe(401)
    expect(sentry).not.toHaveBeenCalled()
  })

  it('stops one sender at 3 an hour, so one sender cannot spend the whole door', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 4; i++)
      statuses.push((await fromOwnPage({ 'cf-connecting-ip': '198.51.100.1' })).status)
    expect(statuses).toEqual([202, 202, 202, 429])
    expect((await fromOwnPage({ 'cf-connecting-ip': '198.51.100.2' })).status).toBe(202)
  })

  it('stops the door at 10 an hour across everyone, without spending a signed-in person’s budget', async () => {
    const statuses: number[] = []
    for (let i = 0; i < 11; i++)
      statuses.push((await fromOwnPage({ 'cf-connecting-ip': `198.51.100.${i}` })).status)
    expect(statuses.slice(0, 10).every((s) => s === 202)).toBe(true)
    expect(statuses[10]).toBe(429)
    // Issued now: the token from the outer setup is older than this block's clock jump.
    const fresh = (await issueToken({ pubkey: personPubkey, clientId: 'estiva-peek' })).token
    expect((await report(fresh, crash)).status).toBe(202)
    expect(sentry).toHaveBeenCalledTimes(11)
  })

  it('stops the door at 50 a day, however the hours are spread', async () => {
    const statuses: number[] = []
    for (let hour = 0; hour < 6; hour++) {
      for (let i = 0; i < 10; i++)
        statuses.push((await fromOwnPage({ 'cf-connecting-ip': `198.51.${hour}.${i}` })).status)
      clock += 61 * 60_000
      vi.setSystemTime(clock)
    }
    expect(statuses.filter((s) => s === 202)).toHaveLength(50)
    expect(statuses.slice(50).every((s) => s === 429)).toBe(true)
  })
})
