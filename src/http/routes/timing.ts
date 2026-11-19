/**
 * `POST /timing` — how long a person waited for an app's page to open, passed
 * on to Sentry.
 * why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/page-open-timings-go-to-sentry-named-by-the-person-built-from-an-allowed-list.md
 *
 *     POST /timing
 *     Authorization: Bearer <jwt issued to this app for this user>
 *     { release, screen, how, waitMs, ready }
 *
 *     202 { sent: boolean }
 *
 * Only a signed-in app can send one: there is no door before sign-in, and
 * Estiva ID's own pages send none. Who sent it and which app are the token's;
 * the timing itself is rebuilt from the allowed list (`domain/page-timings.ts`).
 * Timings count on limits of their own, apart from error reports', so a day of
 * opens never crowds out a crash. Cross-origin like `/report`.
 */
import { Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { accountKind } from '../../domain/error-reports.js'
import { verifyToken } from '../../domain/jwt.js'
import { rebuildTiming, sendTimingToSentry, timingDsnFor } from '../../domain/page-timings.js'
import { badRequest, rateLimited } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { bearerToken } from '../bearer.js'
import { allowOrigin, preflight } from '../cors.js'
import { createRateLimiter } from '../rate-limit.js'

/** A timing is about a hundred bytes. */
const MAX_BODY_BYTES = 2 * 1024

/**
 * Per app and person. A tab sends at most 120 an hour; 300 is a few tabs open
 * all day. Past that it is a loop or a misuse.
 */
const PERSON_PER_HOUR = 300
const personLimiter = createRateLimiter(PERSON_PER_HOUR, 60 * 60_000)

/**
 * Per app, across everyone: Sentry's free month is 5,000,000 spans. Three apps
 * at 1,000 an hour each are at most about 2,200,000 a month.
 */
const APP_PER_HOUR = 1_000
const appLimiter = createRateLimiter(APP_PER_HOUR, 60 * 60_000)

export function timingRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.options('/timing', preflight('POST, OPTIONS', 'authorization, content-type'))

  const sizeCap = bodyLimit({
    maxSize: MAX_BODY_BYTES,
    onError: () => {
      throw badRequest('Timing too large')
    },
  })

  routes.post('/timing', sizeCap, async (c) => {
    await allowOrigin(c)
    const { pubkey, clientId, delegate } = await verifyToken(
      bearerToken(c.req.header('authorization')),
    )

    let body: unknown
    try {
      body = JSON.parse(await c.req.text())
    } catch {
      throw badRequest('Expected a JSON timing')
    }

    const person = personLimiter.check(`${clientId}:${pubkey}`)
    const budget = person.allowed ? appLimiter.check(clientId) : person
    if (!budget.allowed) {
      c.header('retry-after', String(budget.retryAfterSeconds))
      throw rateLimited('Too many timings', {
        reason: 'rate_limited',
        retryAfterSeconds: budget.retryAfterSeconds,
      })
    }

    const dsn = timingDsnFor(clientId)
    if (!dsn) return c.json({ sent: false, reason: 'not_collected' }, 202)

    const timing = rebuildTiming(body, {
      app: clientId,
      pubkey,
      account: await accountKind(pubkey, delegate !== undefined),
      userAgent: c.req.header('user-agent'),
    })
    if (!timing) throw badRequest('Not a timing')

    const log = c.get('log')
    try {
      const result = await sendTimingToSentry(timing, dsn)
      if (!result.sent)
        log.warn({ status: result.status, app: clientId }, 'sentry refused a timing')
      return c.json({ sent: result.sent }, 202)
    } catch (error) {
      log.warn({ err: (error as Error).name, app: clientId }, 'sentry unreachable')
      return c.json({ sent: false }, 202)
    }
  })

  return routes
}
