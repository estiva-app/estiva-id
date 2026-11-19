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
 *
 * Estiva ID's own pages (PROD-4) send from this origin with no token: signed
 * in, their session cookie says who; before sign-in they come through a door
 * with its own small budget, marked `signed-out` and with no public key.
 */
import { type Context, Hono } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { getCookie } from 'hono/cookie'
import { config } from '../../config.js'
import {
  ESTIVA_ID_WEB,
  accountKind,
  rebuildReport,
  sendToSentry,
  sentryDsnFor,
} from '../../domain/error-reports.js'
import { verifyToken } from '../../domain/jwt.js'
import { getActivePubkey } from '../../domain/keys.js'
import { SESSION_COOKIE, peekSession } from '../../domain/sessions.js'
import { badRequest, forbidden, rateLimited, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { bearerToken } from '../bearer.js'
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

/**
 * Per app, across everyone: a few accounts in a loop must not use up Sentry's
 * free month (5,000), so no app sends more than 100 an hour.
 */
const APP_REPORTS_PER_HOUR = 100
const appLimiter = createRateLimiter(APP_REPORTS_PER_HOUR, 60 * 60_000)

/**
 * The door before sign-in (PROD-4): a crash on Estiva ID's own sign-in page
 * happens before anyone is signed in. Only Estiva ID's own origin may use it,
 * and an Origin header can be forged outside a browser, so its budget is what
 * holds: at most 10 an hour and 50 a day across everyone, which is at most
 * 1,500 of Sentry's free 5,000 a month even if somebody spends it all. It
 * spends neither a person's budget nor an app's.
 */
const DOOR_PER_HOUR = 10
const DOOR_PER_DAY = 50
const doorHour = createRateLimiter(DOOR_PER_HOUR, 60 * 60_000)
/**
 * Per sender first, so one sender cannot spend the whole door and starve a
 * real sign-in crash. Keyed on `cf-connecting-ip`, which Cloudflare's tunnel
 * in front of this server sets itself (a client cannot choose it); without it,
 * every sender shares one key and only the global budget holds.
 */
const DOOR_PER_SENDER_PER_HOUR = 3
const doorSender = createRateLimiter(DOOR_PER_SENDER_PER_HOUR, 60 * 60_000)
const doorDay = createRateLimiter(DOOR_PER_DAY, 24 * 60 * 60_000)

/**
 * A failure the page showed, before sign-in (a dead invite link, a passkey
 * that is not registered here; PROD-5), has a door of its own, smaller still:
 * those are common, and must never spend the budget a sign-in crash needs. At
 * most 5 an hour and 20 a day, which is 600 a month beside the crash door's
 * 1,500.
 */
const HANDLED_DOOR_PER_HOUR = 5
const HANDLED_DOOR_PER_DAY = 20
const handledDoorHour = createRateLimiter(HANDLED_DOOR_PER_HOUR, 60 * 60_000)
const handledDoorDay = createRateLimiter(HANDLED_DOOR_PER_DAY, 24 * 60 * 60_000)

/**
 * Failures and refusals (PROD-5) count on keys of their own, so a relay that
 * refuses every tab's writes for an hour cannot use up the budget the crashes
 * in that hour need. Each app may then send up to 100 of each an hour.
 */
function spend(personKey: string, clientId: string, handled: boolean) {
  const suffix = handled ? ':handled' : ''
  const person = limiter.check(`${personKey}${suffix}`)
  return person.allowed ? appLimiter.check(`${clientId}${suffix}`) : person
}

function spendDoor(sender: string, handled: boolean) {
  const own = doorSender.check(handled ? `${sender}:handled` : sender)
  if (!own.allowed) return own
  const hour = (handled ? handledDoorHour : doorHour).check('door')
  return hour.allowed ? (handled ? handledDoorDay : doorDay).check('door') : hour
}

interface Sender {
  clientId: string
  /** Absent only through the door before sign-in. */
  pubkey: string | undefined
  delegated: boolean
  /** The origin whose bundles a frame may name; anything else is `<other>`. */
  appOrigin: string | undefined
}

/**
 * Who sends this report, never from the report itself:
 * - an app on another origin, by the token Estiva ID issued it (`Authorization: Bearer`);
 * - Estiva ID's own pages, by their session cookie;
 * - Estiva ID's own pages before sign-in, through the door, as nobody.
 * A report from any other origin without a token is refused as before.
 */
async function whoSends(c: Context<AppEnv>): Promise<Sender> {
  const authorization = c.req.header('authorization')
  const origin = c.req.header('origin')
  const ownOrigin = new URL(config().ISSUER_URL).origin
  if (authorization || origin !== ownOrigin) {
    const allowed = await allowOrigin(c)
    const { pubkey, clientId, delegate } = await verifyToken(bearerToken(authorization))
    return {
      clientId,
      pubkey,
      delegated: delegate !== undefined,
      appOrigin: allowed ? origin : undefined,
    }
  }

  const cookie = getCookie(c, SESSION_COOKIE)
  // Not a use of the session: a crashing page must not keep an idle one alive.
  const session = cookie ? await peekSession(cookie) : undefined
  const pubkey = session ? await getActivePubkey(session.userId) : undefined
  // Signed in with no key to name (offboarded in another tab): neither a person nor nobody.
  if (session && !pubkey) throw unauthenticated('No active key for this session')
  return {
    clientId: ESTIVA_ID_WEB,
    pubkey,
    delegated: session?.delegate !== undefined,
    appOrigin: ownOrigin,
  }
}

export function reportRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.options('/report', preflight('POST, OPTIONS', 'authorization, content-type'))

  // Counted on the stream, in bytes, so an oversized body is refused before it is read.
  const sizeCap = bodyLimit({
    maxSize: MAX_BODY_BYTES,
    onError: () => {
      throw badRequest('Report too large')
    },
  })

  routes.post('/report', sizeCap, async (c) => {
    const sender = await whoSends(c)
    const { pubkey, clientId, appOrigin } = sender

    const raw = await c.req.text()
    let body: unknown
    try {
      body = JSON.parse(raw)
    } catch {
      throw badRequest('Expected a JSON report')
    }

    // The person's budget first, so one person's loop does not spend the app's.
    // Before sign-in there is no person to count: the door has its own, small one.
    const how = (body as { how?: unknown } | null)?.how
    const handled = how === 'failure' || how === 'refused'
    const budget = pubkey
      ? spend(`${clientId}:${pubkey}`, clientId, handled)
      : spendDoor(c.req.header('cf-connecting-ip') ?? 'direct', handled)
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
      appOrigin,
      pubkey,
      account: pubkey ? await accountKind(pubkey, sender.delegated) : 'signed-out',
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

  /**
   * The known test request for the server's own reports (PROD-6): a QA
   * account's sign-in makes a server error on purpose, through the same error
   * handler as any other. Anyone else is refused, and a refusal is never
   * reported, so a stranger cannot use it to fill Sentry.
   */
  routes.post('/report/server-error-on-purpose', async (c) => {
    const { pubkey, delegated } = await whoSends(c)
    if (!pubkey) throw unauthenticated('Sign in as a QA account')
    const account = await accountKind(pubkey, delegated)
    if (account !== 'qa') throw forbidden('Only a QA account can make a server error on purpose')
    c.set('reportAs', { pubkey, account })
    makeServerErrorOnPurpose()
  })

  return routes
}

class ServerErrorOnPurpose extends Error {
  override name = 'ServerErrorOnPurpose'
}

function makeServerErrorOnPurpose(): never {
  throw new ServerErrorOnPurpose('A server error made on purpose by a QA account')
}
