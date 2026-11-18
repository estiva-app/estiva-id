/**
 * `POST /report` — an app's error report, passed on to Sentry.
 *
 *     POST /report
 *     Authorization: Bearer <jwt issued to this app for this user>
 *     { release, how, error: { type, message, frames }, screen, trail }
 *
 *     202 { sent: boolean }
 *
 * Only a signed-in app can send one, so nobody outside can fill Sentry's month
 * or write text that Claude later reads. Who sent it and which app are the
 * token's, never the report's; the report itself is rebuilt from the allowed
 * list (`domain/error-reports.ts`). Sentry sees this server, not the person's
 * IP address, and only this server knows where Sentry is (`SENTRY_DSNS`).
 *
 * Cross-origin like `/sign`: the apps are static bundles on other origins, and
 * the allowlist is the registered redirect URIs (`http/cors.ts`).
 */
import { Hono } from 'hono'
import {
  accountKind,
  rebuildReport,
  sendToSentry,
  sentryDsnFor,
} from '../../domain/error-reports.js'
import { verifyToken } from '../../domain/jwt.js'
import { badRequest, rateLimited, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { allowOrigin, preflight } from '../cors.js'
import { createRateLimiter } from '../rate-limit.js'

/** A report is a few KB; anything much larger is not one of ours. */
const MAX_BODY_BYTES = 32 * 1024

/**
 * Per app and person. The reporter sends each kind of error once per tab and
 * at most ten per tab, so 30 in ten minutes is several tabs reloading into the
 * same crash; past that it is a loop or a misuse, and Sentry's free month is
 * 5,000.
 */
const REPORTS_PER_WINDOW = 30
const WINDOW_MS = 10 * 60_000
const limiter = createRateLimiter(REPORTS_PER_WINDOW, WINDOW_MS)

/** Test seam. */
export const resetReportRateLimitForTests = () => limiter.reset()

function bearerToken(header: string | undefined): string {
  if (!header?.startsWith('Bearer ')) throw unauthenticated('Expected a Bearer token')
  const token = header.slice('Bearer '.length).trim()
  if (!token) throw unauthenticated('Empty Bearer token')
  return token
}

export function reportRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.options('/report', preflight('POST, OPTIONS', 'authorization, content-type'))

  routes.post('/report', async (c) => {
    const allowed = await allowOrigin(c)
    const { pubkey, clientId, delegate } = await verifyToken(
      bearerToken(c.req.header('authorization')),
    )

    const raw = await c.req.text()
    if (raw.length > MAX_BODY_BYTES) throw badRequest('Report too large')
    let body: unknown
    try {
      body = JSON.parse(raw)
    } catch {
      throw badRequest('Expected a JSON report')
    }

    const budget = limiter.check(`${clientId}:${pubkey}`)
    if (!budget.allowed) {
      c.header('retry-after', String(budget.retryAfterSeconds))
      throw rateLimited('Too many error reports', {
        reason: 'rate_limited',
        retryAfterSeconds: budget.retryAfterSeconds,
      })
    }

    const dsn = sentryDsnFor(clientId)
    if (!dsn) return c.json({ sent: false, reason: 'not_collected' }, 202)

    const now = Date.now()
    const report = rebuildReport(body, {
      app: clientId,
      appOrigin: allowed ? c.req.header('origin') : undefined,
      pubkey,
      account: await accountKind(pubkey, delegate !== undefined),
      userAgent: c.req.header('user-agent'),
      now,
    })

    const log = c.get('log')
    try {
      const result = await sendToSentry(report, dsn, now)
      if (!result.sent)
        log.warn({ status: result.status, app: clientId }, 'sentry refused a report')
      return c.json({ sent: result.sent }, 202)
    } catch (error) {
      log.warn({ err: (error as Error).name, app: clientId }, 'sentry unreachable')
      return c.json({ sent: false }, 202)
    }
  })

  return routes
}
