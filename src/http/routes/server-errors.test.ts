/**
 * The known test request for Estiva ID's server reports (PROD-6): a QA account
 * makes a server error on purpose, it reaches Sentry under the server with
 * nothing of the request, and nobody else can use it.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigForTests } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const ORIGIN = 'http://localhost:5190'
const SERVER_DSN = 'https://srv456@o1.ingest.de.sentry.io/77'
const RELEASE = 'c0ffee1234abcd'
const PLANTED = 'plantedbody quarterly numbers'

let app: ReturnType<typeof createApp>
let personToken: string
let qaToken: string
let qaPubkey: string
let sentry: ReturnType<typeof vi.fn>

/**
 * The error handler answers without waiting on Sentry. A report on this route
 * needs no lookup, so a few turns of the event loop settle it; the tests that
 * expect a report assert it arrived, so a slower path fails loudly.
 */
const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setImmediate(resolve))
}

const sentEnvelopes = () => sentry.mock.calls.map((call) => String((call[1] as RequestInit).body))
const sentEvent = () => JSON.parse(sentEnvelopes()[0]?.split('\n')[2] ?? 'null')

function onPurpose(token: string | undefined) {
  return app.request('/report/server-error-on-purpose', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
      cookie: 'estiva_session=plantedcookie123',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ note: PLANTED, email: 'ada@example.test' }),
  })
}

// The ceilings keep their windows in process memory: each test starts two days after the last.
let clock = Date.now()

beforeAll(async () => {
  process.env.SENTRY_DSNS = `estiva-id-server=${SERVER_DSN}`
  process.env.RELEASE = RELEASE
  resetConfigForTests()
  await prepareDatabase()
  app = createApp()
})

beforeEach(async () => {
  vi.useFakeTimers({ toFake: ['Date'] })
  clock += 2 * 24 * 60 * 60_000
  vi.setSystemTime(clock)
  await truncateAll()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [`${ORIGIN}/auth/callback`],
    'estiva-peek',
  ])
  const ada = await createUserWithKey({ email: 'ada@example.test' })
  personToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
  const qa = await createUserWithKey({ email: 'qa-1@example.test', testAccount: true })
  qaPubkey = qa.pubkey
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
  Reflect.deleteProperty(process.env, 'RELEASE')
  resetConfigForTests()
  await closePool()
})

describe('POST /report/server-error-on-purpose', () => {
  it("answers a QA account with the server's 500 and sends Sentry one report under the server and its release", async () => {
    const response = await onPurpose(qaToken)
    expect(response.status).toBe(500)
    expect(await response.json()).toMatchObject({ error: { code: 'internal' } })
    await settle()

    expect(sentry).toHaveBeenCalledTimes(1)
    expect(String(sentry.mock.calls[0]?.[0])).toBe(
      'https://o1.ingest.de.sentry.io/api/77/envelope/',
    )
    const event = sentEvent()
    expect(event).toMatchObject({
      platform: 'node',
      release: RELEASE,
      transaction: 'POST /report/server-error-on-purpose',
      user: { id: qaPubkey },
      tags: { app: 'estiva-id-server', account: 'qa' },
    })
    const [exception] = event.exception.values
    expect(exception.type).toBe('ServerErrorOnPurpose')
    expect(exception.mechanism).toEqual({ type: 'onerror', handled: false })
    // Oldest call first, as Sentry reads them: the throw is the last frame.
    expect(exception.stacktrace.frames.at(-1)).toMatchObject({
      function: 'makeServerErrorOnPurpose',
      abs_path: 'src/http/routes/report.ts',
      in_app: true,
    })
    expect(event.contexts).toEqual({ runtime: { name: 'node', version: expect.any(String) } })
  })

  it('sends Sentry no token, cookie, email, request body or address', async () => {
    await onPurpose(qaToken)
    await settle()

    expect(sentry).toHaveBeenCalledTimes(1)
    const envelope = sentEnvelopes().join('\n')
    expect(envelope).not.toContain(qaToken)
    expect(envelope).not.toContain('plantedcookie123')
    expect(envelope).not.toContain('plantedbody')
    expect(envelope).not.toContain('example.test')
    expect(envelope).not.toContain('localhost')
    expect(envelope).not.toMatch(/authorization|cookie|ip_address|"request"/i)
  })

  it('refuses a signed-in person who is not a QA account, and reports nothing', async () => {
    const response = await onPurpose(personToken)
    expect(response.status).toBe(403)
    await settle()
    expect(sentry).not.toHaveBeenCalled()
  })

  it('refuses a request with no sign-in, and reports nothing', async () => {
    const response = await onPurpose(undefined)
    expect(response.status).toBe(401)
    await settle()
    expect(sentry).not.toHaveBeenCalled()
  })
})
