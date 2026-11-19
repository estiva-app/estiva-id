/**
 * Page-open timings: how long a person waited for a page of an app to open,
 * rebuilt here from a fixed list and passed on to Sentry as a transaction
 * (stored there as a span, the wait its duration).
 * why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/page-open-timings-go-to-sentry-named-by-the-person-built-from-an-allowed-list.md
 *
 * A timing holds the app and its version, the kind of screen (the same names
 * error reports use), how the page was opened, the wait and how its end was
 * found, when, the browser, the person's public key and what kind of account
 * it is. Never an address, a title, which file was opened, any text, or the
 * person's IP address: Sentry sees this server, and the event names none.
 */
import { randomBytes } from 'node:crypto'
import { config } from '../config.js'
import {
  type AccountKind,
  RELEASE,
  type Software,
  dsnFor,
  parseDsn,
  readBrowser,
  readScreen,
} from './error-reports.js'

export type OpenHow = 'new-tab' | 'reload' | 'in-app'
export type OpenReady = 'placeholder-gone' | 'no-placeholder' | 'gave-up' | 'left'

const HOWS: ReadonlySet<string> = new Set<OpenHow>(['new-tab', 'reload', 'in-app'])
const READIES: ReadonlySet<string> = new Set<OpenReady>([
  'placeholder-gone',
  'no-placeholder',
  'gave-up',
  // The person left a page still loading: counted apart (Miky, 19 Nov).
  'left',
])

/** The browser gives up at a minute; anything longer is not one of ours. */
export const MAX_WAIT_MS = 60_000

export interface PageTiming {
  app: string
  release: string
  screen: string
  how: OpenHow
  waitMs: number
  ready: OpenReady
  /** Peek: when the page load's saved picture showed, from the same start as the wait. A second number, never the wait (Miky, 19 Nov). */
  pictureMs?: number
  browser: Software
  pubkey: string
  account: AccountKind
}

/**
 * Builds the timing from the list. `body` is whatever the browser sent; the
 * rest is what this server knows for itself. A timing whose how, ready or wait
 * is not one of ours is no timing: `undefined`.
 */
export function rebuildTiming(
  body: unknown,
  known: { app: string; pubkey: string; account: AccountKind; userAgent: string | undefined },
): PageTiming | undefined {
  const input = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>
  const { how, ready, waitMs } = input
  if (typeof how !== 'string' || !HOWS.has(how)) return undefined
  if (typeof ready !== 'string' || !READIES.has(ready)) return undefined
  if (typeof waitMs !== 'number' || !Number.isInteger(waitMs) || waitMs < 0 || waitMs > MAX_WAIT_MS)
    return undefined
  // Optional: a picture number that is not one of ours is left out, and the wait still counts.
  // The saved picture shows before the live page, so never after the wait.
  const { pictureMs } = input
  const picture =
    typeof pictureMs === 'number' &&
    Number.isInteger(pictureMs) &&
    pictureMs >= 0 &&
    pictureMs <= waitMs
      ? { pictureMs }
      : {}
  return {
    ...picture,
    app: known.app,
    release:
      typeof input.release === 'string' && RELEASE.test(input.release) ? input.release : 'unknown',
    screen: readScreen(known.app, input.screen) ?? '<unknown>',
    how: how as OpenHow,
    waitMs,
    ready: ready as OpenReady,
    browser: readBrowser(known.userAgent),
    pubkey: known.pubkey,
    account: known.account,
  }
}

/**
 * `client_id=dsn` pairs from `TIMINGS_DSNS`, apart from `SENTRY_DSNS`: a
 * deployment that sends its errors somewhere sends no timings until it names a
 * place for them too.
 */
export function timingDsnFor(clientId: string): string | undefined {
  return dsnFor(config().TIMINGS_DSNS, clientId)
}

/** The Sentry transaction: exactly the timing's fields, and no request, IP address or extra. */
export function sentryTransaction(timing: PageTiming, eventId: string, now: number) {
  return {
    event_id: eventId,
    type: 'transaction',
    // Not `javascript`: Sentry fills a javascript event's missing IP address
    // from whoever sent it, and this server's address is not one to keep either.
    platform: 'other',
    transaction: `open ${timing.screen}`,
    transaction_info: { source: 'custom' },
    start_timestamp: (now - timing.waitMs) / 1000,
    timestamp: now / 1000,
    release: timing.release,
    environment: 'production',
    user: { id: timing.pubkey },
    tags: {
      app: timing.app,
      account: timing.account,
      screen: timing.screen,
      how: timing.how,
      ready: timing.ready,
      browser: timing.browser.name,
    },
    contexts: {
      trace: {
        trace_id: randomBytes(16).toString('hex'),
        span_id: randomBytes(8).toString('hex'),
        op: 'page.open',
        status: 'ok',
      },
      browser: {
        name: timing.browser.name,
        ...(timing.browser.version ? { version: timing.browser.version } : {}),
      },
    },
    spans: [],
    ...(timing.pictureMs !== undefined
      ? { measurements: { picture: { value: timing.pictureMs, unit: 'millisecond' } } }
      : {}),
  }
}

/** Sends the timing to Sentry's envelope endpoint. Returns whether Sentry took it. */
export async function sendTimingToSentry(
  timing: PageTiming,
  dsn: string,
  now = Date.now(),
): Promise<{ sent: boolean; status?: number }> {
  const target = parseDsn(dsn)
  if (!target) return { sent: false }
  const eventId = randomBytes(16).toString('hex')
  const body = [
    JSON.stringify({ event_id: eventId, sent_at: new Date(now).toISOString(), dsn: target.dsn }),
    JSON.stringify({ type: 'transaction' }),
    JSON.stringify(sentryTransaction(timing, eventId, now)),
  ].join('\n')
  const response = await fetch(target.envelopeUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-sentry-envelope',
      'x-sentry-auth': `Sentry sentry_version=7, sentry_key=${target.publicKey}, sentry_client=estiva-id/1`,
    },
    body,
    signal: AbortSignal.timeout(5_000),
  })
  return { sent: response.ok, status: response.status }
}
