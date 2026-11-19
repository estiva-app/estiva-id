/**
 * What Estiva ID's server sends Sentry about its own errors (PROD-6), and the
 * ceilings that keep a loop from spending the month.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { resetConfigForTests } from '../config.js'
import { logger } from '../logger.js'
import { reportServerError, serverReport } from './server-errors.js'

const SERVER_DSN = 'https://srv456@o1.ingest.de.sentry.io/77'
const RELEASE = 'c0ffee1234abcd'
const PLANTED = 'plantedbody quarterly numbers'
const PUBKEY = 'a'.repeat(64)

let sentry: ReturnType<typeof vi.fn>
const sentEvents = () =>
  sentry.mock.calls.map((call) =>
    JSON.parse(String((call[1] as RequestInit).body).split('\n')[2] ?? 'null'),
  )

// The ceilings keep their windows in process memory: each test starts two days after the last.
let clock = Date.now()

beforeAll(() => {
  process.env.SENTRY_DSNS = `estiva-id-server=${SERVER_DSN}`
  process.env.RELEASE = RELEASE
  resetConfigForTests()
})

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date', 'setTimeout'] })
  clock += 2 * 24 * 60 * 60_000
  vi.setSystemTime(clock)
  sentry = vi.fn(async () => new Response('{}', { status: 200 }))
  vi.stubGlobal('fetch', sentry)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

afterAll(() => {
  process.env.SENTRY_DSNS = ''
  Reflect.deleteProperty(process.env, 'RELEASE')
  resetConfigForTests()
})

/** A distinct kind of error: its own type, so the ceilings count it apart. */
function kind(name: string) {
  const error = new Error('boom')
  error.name = name
  return error
}

describe('reportServerError', () => {
  it('sends an error from outside our own code, repeated in a loop, three times, not up to the hourly cap', async () => {
    for (let i = 0; i < 20; i++) {
      const error = new Error('socket hang up')
      error.stack = 'Error: socket hang up\n    at Socket.onend (node:_http_client:1:1)'
      await reportServerError(error, { how: 'error' }, logger)
    }
    expect(sentry).toHaveBeenCalledTimes(3)
  })

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
      await reportServerError(kind(`Kind${i}Error`), { how: 'error' }, logger)
    }
    expect(sentry).toHaveBeenCalledTimes(10)
  })

  it('names who was signed in when the lookup finds them', async () => {
    await reportServerError(
      kind('LookupFoundError'),
      { how: 'error', as: async () => ({ pubkey: PUBKEY, account: 'person' }) },
      logger,
    )
    expect(sentEvents()[0]).toMatchObject({ user: { id: PUBKEY }, tags: { account: 'person' } })
  })

  it('still sends the report, naming no one, when the lookup fails', async () => {
    await reportServerError(
      kind('LookupFailedError'),
      {
        how: 'error',
        as: async () => {
          throw new Error('database unreachable')
        },
      },
      logger,
    )
    expect(sentry).toHaveBeenCalledTimes(1)
    expect(sentEvents()[0].user).toBeUndefined()
  })

  it('still sends the report after a second when the lookup hangs, as on a database that stopped answering', async () => {
    const sending = reportServerError(
      kind('LookupHangsError'),
      { how: 'error', as: () => new Promise(() => {}) },
      logger,
    )
    await vi.advanceTimersByTimeAsync(999)
    expect(sentry).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    await sending
    expect(sentry).toHaveBeenCalledTimes(1)
    expect(sentEvents()[0].user).toBeUndefined()
  })

  it('does not look anyone up once the ceiling has stopped that kind of error', async () => {
    const lookup = vi.fn(async () => ({ pubkey: PUBKEY, account: 'person' as const }))
    for (let i = 0; i < 20; i++) {
      await reportServerError(kind('LoopError'), { how: 'error', as: lookup }, logger)
    }
    expect(sentry).toHaveBeenCalledTimes(3)
    expect(lookup).toHaveBeenCalledTimes(3)
  })

  it('reports an error that ended the process as uncaught, with no one signed in', async () => {
    await reportServerError(new RangeError('boom'), { how: 'uncaught-exception' }, logger)
    const [event] = sentEvents()
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
    const route = (r: string) => serverReport(new Error('x'), { how: 'error', route: r }).screen
    expect(route('GET /admin/people/:id')).toBe('GET /admin/people/:id')
    expect(route('GET /x?q=plantedbody quarterly')).toBe('<none>')
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
