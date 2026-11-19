/**
 * Estiva ID's server reports its own errors to Sentry (PROD-6): the known test
 * request, what a report may hold, and the ceiling that keeps a loop from
 * spending the month.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigForTests } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { reportServerError, serverReport } from '../../domain/server-errors.js'
import { createUserWithKey } from '../../domain/users.js'
import { logger } from '../../logger.js'
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

/** Settles the reports a request started without waiting on (microtasks only, no clock). */
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

describe("the server's reports", () => {
  it('sends the same error made 1,000 times in a minute three times, not 1,000', async () => {
    const error = new TypeError('Cannot read properties of undefined')
    for (let i = 0; i < 1_000; i++) {
      vi.setSystemTime(clock + i * 60)
      await reportServerError(error, { how: 'error', route: 'GET /healthz' }, logger)
    }
    expect(sentry).toHaveBeenCalledTimes(3)
  })

  it('stops every kind of error together at ten an hour', async () => {
    for (let i = 0; i < 30; i++) {
      const error = new Error('boom')
      error.name = `Kind${i}Error`
      await reportServerError(error, { how: 'error' }, logger)
    }
    expect(sentry).toHaveBeenCalledTimes(10)
  })

  it('reports an error that ended the process as uncaught, with no one signed in', async () => {
    await reportServerError(new RangeError('boom'), { how: 'uncaught-exception' }, logger)
    const event = sentEvent()
    expect(event.exception.values[0].mechanism.type).toBe('onuncaughtexception')
    expect(event.user).toBeUndefined()
    expect(event.tags.account).toBeUndefined()
    expect(event.transaction).toBe('<none>')
  })

  it('sends nothing when the server has no Sentry address', async () => {
    process.env.SENTRY_DSNS = `estiva-peek=${SERVER_DSN}`
    resetConfigForTests()
    try {
      await reportServerError(new Error('boom'), { how: 'error' }, logger)
      expect(sentry).not.toHaveBeenCalled()
    } finally {
      process.env.SENTRY_DSNS = `estiva-id-server=${SERVER_DSN}`
      resetConfigForTests()
    }
  })
})

describe('serverReport', () => {
  it("removes quoted text from the error's wording", () => {
    const report = serverReport(
      new SyntaxError(`Unexpected token 'p', "${PLANTED}" is not valid JSON`),
      { how: 'error' },
    )
    expect(report.type).toBe('SyntaxError')
    expect(report.message).not.toContain('plantedbody')
  })

  it('keeps a frame of our own files and drops the name and place of any other', () => {
    const error = new Error('boom')
    error.stack = [
      'Error: boom',
      `    at ownFunction (file://${process.cwd()}/src/domain/users.ts:10:5)`,
      `    at libFunction (file://${process.cwd()}/node_modules/hono/dist/x.js:1:2)`,
      '    at process.processTicksAndRejections (node:internal/process/task_queues:95:5)',
      `    at /home/someone/${PLANTED.replaceAll(' ', '-')}/x.js:1:1`,
    ].join('\n')
    expect(serverReport(error, { how: 'error' }).frames).toEqual([
      { function: 'ownFunction', absPath: 'src/domain/users.ts', line: 10, column: 5 },
      { absPath: '<other>' },
      { absPath: '<other>' },
      { absPath: '<other>' },
    ])
  })

  it('names the route by its pattern only, never a path a person typed', () => {
    expect(
      serverReport(new Error('x'), { how: 'error', route: 'GET /admin/people/:id' }).screen,
    ).toBe('GET /admin/people/:id')
    expect(
      serverReport(new Error('x'), { how: 'error', route: 'GET /x?q=plantedbody quarterly' })
        .screen,
    ).toBe('<none>')
  })

  it("sends the release as unknown when the image's is not a commit", () => {
    process.env.RELEASE = 'not a sha'
    try {
      expect(serverReport(new Error('x'), { how: 'error' }).release).toBe('unknown')
    } finally {
      process.env.RELEASE = RELEASE
    }
  })
})
