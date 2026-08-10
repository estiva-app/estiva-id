/**
 * The Hono application: middleware, error handling, and route mounting.
 *
 * Routes are added by later checkpoints; what is fixed here is the envelope
 * every route shares — a request id, a bound logger, and one error shape.
 */
import { randomUUID } from 'node:crypto'
import { Hono } from 'hono'
import { query } from '../db/pool.js'
import { AppError, toErrorBody } from '../errors.js'
import { type Logger, logger } from '../logger.js'
import { adminRoutes } from './routes/admin.js'
import { authRoutes } from './routes/auth.js'
import { authorizeRoutes } from './routes/authorize.js'
import { inviteRoutes } from './routes/invites.js'
import { profileRoutes } from './routes/profile.js'
import { signRoutes } from './routes/sign.js'
import { tokenRoutes } from './routes/tokens.js'
import { mountUi, uiIsBuilt } from './ui.js'

export interface AppEnv {
  Variables: {
    requestId: string
    log: Logger
    /** Set by `requireSession`. Absent on unauthenticated routes. */
    session: { id: string; userId: string }
  }
}

export function createApp(): Hono<AppEnv> {
  const app = new Hono<AppEnv>()

  app.use('*', async (c, next) => {
    const requestId = c.req.header('x-request-id') ?? randomUUID()
    const log = logger.child({ requestId })
    c.set('requestId', requestId)
    c.set('log', log)
    c.header('x-request-id', requestId)

    const startedAt = performance.now()
    await next()
    log.info(
      {
        method: c.req.method,
        path: c.req.path,
        status: c.res.status,
        durationMs: Math.round(performance.now() - startedAt),
      },
      'request',
    )
  })

  // Liveness: the process is up. Never touches the database, so a Postgres
  // outage does not get the container restarted.
  app.get('/healthz', (c) => c.json({ status: 'ok' }))

  // Readiness: the process can actually serve. A DB round-trip, because every
  // meaningful route needs one.
  app.get('/readyz', async (c) => {
    try {
      await query('select 1')
      return c.json({ status: 'ok', database: 'ok' })
    } catch (error) {
      c.get('log').error({ err: error }, 'readiness check failed')
      return c.json({ status: 'degraded', database: 'unreachable' }, 503)
    }
  })

  app.route('/', authRoutes())
  app.route('/', authorizeRoutes())
  app.route('/', inviteRoutes())
  app.route('/', tokenRoutes())
  app.route('/', signRoutes())
  app.route('/', profileRoutes())
  app.route('/', adminRoutes())

  // After the API routes, so the UI's catch-all can never shadow one, and only
  // when a build is present — see ui.ts.
  if (uiIsBuilt()) mountUi(app)

  app.notFound((c) =>
    c.json(
      toErrorBody(new AppError('not_found', `No route for ${c.req.method} ${c.req.path}`)),
      404,
    ),
  )

  app.onError((error, c) => {
    if (error instanceof AppError) {
      // Expected refusals are information, not incidents — log at warn so the
      // signal from a real fault is not buried by policy denials.
      c.get('log')?.warn({ code: error.code, detail: error.detail }, error.message)
      return c.json(toErrorBody(error), error.status as 400)
    }
    c.get('log')?.error({ err: error }, 'unhandled error')
    return c.json(toErrorBody(new AppError('internal', 'Internal server error')), 500)
  })

  return app
}
