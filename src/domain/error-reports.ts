/**
 * Error reports: rebuilt from a fixed list of fields, then sent on to Sentry.
 *
 * An app's reporter already builds its report from this list. This server
 * builds it again, from scratch, so a field the list does not name never
 * reaches Sentry whatever the browser sent, and the parts that are not the
 * browser's to say (who sent it, which app, which browser) are taken from the
 * sign-in and the request, never from the report.
 *
 * The apps decrypt direct messages and private documents in the browser, so an
 * error's own wording may quote what a person wrote: a JSON parse error quotes
 * its input. Wording is kept only with quoted text, addresses and long ids
 * removed ({@link scrubMessage}).
 */
import { randomBytes } from 'node:crypto'
import { config } from '../config.js'
import { queryOne } from '../db/pool.js'

/** Who sent it, by the sign-in: a person, a QA account, or an agent. */
export type AccountKind = 'person' | 'qa' | 'agent'

export interface ReportFrame {
  function?: string
  /** `<app origin>/assets/<file>.js`, or `<other>` for anything else. */
  absPath: string
  line?: number
  column?: number
}

export interface ReportStep {
  at: number
  /** A screen pattern (`/app/teams/:id`) or one of our named actions (`write-refused`). */
  screen?: string
  action?: string
}

/** The whole report, as Sentry will see it. Nothing outside these fields is sent. */
export interface ErrorReport {
  app: string
  release: string
  how: 'error' | 'unhandled-rejection' | 'boundary'
  type: string
  message: string
  frames: ReportFrame[]
  screen: string
  browser: { name: string; version?: string }
  pubkey: string
  account: AccountKind
  trail: ReportStep[]
}

const MAX_MESSAGE = 200
const MAX_FRAMES = 50
const MAX_TRAIL = 10
const TRAIL_MAX_AGE_MS = 24 * 60 * 60 * 1000

const QUOTES = /["'`‘’“”«»]/

/**
 * An error's own wording with what may have been written by a person removed:
 * everything from the first quote mark to the last (an unpaired one to the
 * end), web and mail addresses, Nostr bech32 ids, and any run of 16 or more
 * letters and digits with a digit in it (keys, event ids, tokens). Firefox's URL error names its
 * input without quotes, so it keeps only its own words.
 */
export function scrubMessage(raw: unknown): string {
  if (typeof raw !== 'string') return ''
  let text = raw.replace(/\p{Cc}+/gu, ' ')

  // An apostrophe inside a word (Firefox's "can't access property") is wording, not a quote.
  const isQuote = (i: number) =>
    QUOTES.test(text[i] as string) &&
    !(/\p{L}/u.test(text[i - 1] ?? '') && /\p{L}/u.test(text[i + 1] ?? ''))
  let first = -1
  for (let i = 0; i < text.length; i++) {
    if (isQuote(i)) {
      first = i
      break
    }
  }
  if (first >= 0) {
    let last = -1
    for (let i = text.length - 1; i > first; i--) {
      if (isQuote(i)) {
        last = i
        break
      }
    }
    text = `${text.slice(0, first)}…${last > first ? text.slice(last + 1) : ''}`
  }

  text = text
    // Wordings that name their input without quotes keep only their own words.
    // Firefox: "URL constructor: X is …", "Window.fetch: X is …"; the API's name is kept.
    .replace(
      /^(?:(URL constructor|[A-Z][A-Za-z]*\.[A-Za-z]+): )?.* is not a valid URL\.?$/s,
      (_all, api: string | undefined) =>
        api ? `${api}: … is not a valid URL.` : '… is not a valid URL.',
    )
    .replace(/\b(Failed to parse URL from|Invalid regular expression:|Invalid URL:)\s.*$/s, '$1 …')
    .replace(
      /^Cannot convert .* to an? (BigInt|Symbol|number|string|object|primitive value)\b.*$/s,
      'Cannot convert … to a $1',
    )
    // A web address runs to the end: one with a space in it would leave the rest behind.
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/.*$/is, '<url>')
    .replace(/\S+@\S+\.\S+/g, '<address>')
    .replace(/\b(npub|nsec|note|nevent|naddr|nprofile|nrelay)1[0-9a-z]+/gi, '<id>')
    // A key, event id or token has digits; a long code name (`useLiveTopicSubscription`) has none.
    .replace(/[A-Za-z0-9+/=_-]{16,}/g, (run) => (/\d/.test(run) ? '<id>' : run))
    .replace(/\s+/g, ' ')
    .trim()

  return text.length > MAX_MESSAGE ? `${text.slice(0, MAX_MESSAGE - 1)}…` : text
}

/**
 * Each app's screens, as its router names them. A screen not listed here is
 * sent as `<unknown>`: an app that adds a route adds it here, and until then
 * loses only the name of the screen, never leaks an address.
 */
const SCREENS: Record<string, ReadonlySet<string>> = {
  'estiva-peek': new Set([
    '/',
    '/:word/:ref',
    '/app',
    '/app/desk',
    '/app/dms',
    '/app/dms/:id',
    '/app/folders',
    '/app/folders/:id',
    '/app/folders/:id/chat',
    '/app/initiatives',
    '/app/initiatives/explore',
    '/app/people',
    '/app/people/:id',
    '/app/teams',
    '/app/teams/:id',
    '/app/teams/:id/chat',
    '/app/topics',
    '/app/topics/explore',
    '/auth/callback',
    '/desk',
    '/folders',
    '/folders/:id',
    '/folders/:id/chat',
    '/message/:ref',
    '/o/:ref',
    '/people',
    '/people/:id',
    '/topic-old/:ref',
    '/topics',
    '/topics/:id',
  ]),
}

/**
 * Our own named actions, the only words a step may carry besides a screen
 * (Decided: "kinds of screen and our own named actions only"). Adding one is
 * a change to the list, reviewed as one.
 */
const ACTIONS: ReadonlySet<string> = new Set(['sent-message', 'write-refused'])

/** A route pattern the app is known to have: `/app/teams/:id`, never an address. */
export function readScreen(app: string, raw: unknown): string | undefined {
  return typeof raw === 'string' && SCREENS[app]?.has(raw) ? raw : undefined
}

/** A function as a stack names it: `parseBody`, `Object.<anonymous>`, `new Foo`, `async run`. */
const FUNCTION_NAME =
  /^(?:new |async )?[A-Za-z_$<][\w$<>]{0,60}(?:\.[A-Za-z_$<][\w$<>]{0,60}){0,4}$/
const ASSET_PATH = /^\/assets\/[A-Za-z0-9_.-]{1,100}\.m?js$/
const RELEASE = /^[0-9a-f]{7,40}$/
const TYPE = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/

const intIn = (value: unknown, max: number): number | undefined =>
  typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max
    ? value
    : undefined

/** A frame's file is kept only when it is one of the app's own bundles, on its own origin. */
function readFrame(raw: unknown, appOrigin: string | undefined): ReportFrame | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const frame = raw as Record<string, unknown>
  let absPath = '<other>'
  if (appOrigin && typeof frame.file === 'string') {
    try {
      const url = new URL(frame.file)
      if (url.origin === appOrigin && ASSET_PATH.test(url.pathname) && !url.search && !url.hash) {
        absPath = `${url.origin}${url.pathname}`
      }
    } catch {
      // not a URL: stays <other>
    }
  }
  const kept = absPath !== '<other>'
  return {
    // A frame outside our bundles keeps no name either: it is not our code's word.
    ...(kept && typeof frame.function === 'string' && FUNCTION_NAME.test(frame.function)
      ? { function: frame.function }
      : {}),
    absPath,
    ...(kept && intIn(frame.line, 10_000_000) !== undefined ? { line: frame.line as number } : {}),
    ...(kept && intIn(frame.column, 10_000_000) !== undefined
      ? { column: frame.column as number }
      : {}),
  }
}

function readStep(app: string, raw: unknown, now: number): ReportStep | undefined {
  if (!raw || typeof raw !== 'object') return undefined
  const step = raw as Record<string, unknown>
  const at = intIn(step.at, Number.MAX_SAFE_INTEGER)
  if (at === undefined || at > now + 60_000 || at < now - TRAIL_MAX_AGE_MS) return undefined
  const screen = readScreen(app, step.screen)
  if (screen) return { at, screen }
  if (typeof step.action === 'string' && ACTIONS.has(step.action))
    return { at, action: step.action }
  return undefined
}

/** The browser's family and major version, from the request's own User-Agent. */
export function readBrowser(userAgent: string | undefined): ErrorReport['browser'] {
  const ua = userAgent ?? ''
  const pick = (name: string, pattern: RegExp) => {
    const match = ua.match(pattern)
    return match ? { name, version: match[1] as string } : undefined
  }
  return (
    pick('Edge', /\bEdg(?:A|iOS)?\/(\d{1,4})/) ??
    pick('Opera', /\bOPR\/(\d{1,4})/) ??
    pick('Samsung Internet', /\bSamsungBrowser\/(\d{1,4})/) ??
    pick('Firefox', /\b(?:Firefox|FxiOS)\/(\d{1,4})/) ??
    pick('Chrome', /\b(?:Chrome|CriOS)\/(\d{1,4})/) ??
    pick('Safari', /\bVersion\/(\d{1,4})[^ ]* (?:Mobile\/\S+ )?Safari\//) ?? { name: 'Other' }
  )
}

/** QA accounts are marked by Estiva ID; a delegated token or a role identity is an agent. */
export async function accountKind(pubkey: string, delegated: boolean): Promise<AccountKind> {
  if (delegated) return 'agent'
  const row = await queryOne<{ test_account: boolean; kind: string }>(
    `select u.test_account, u.kind
       from user_keys k join users u on u.id = k.user_id
      where k.pubkey = $1 and k.status = 'active'`,
    [pubkey],
  )
  if (row?.test_account) return 'qa'
  if (row?.kind === 'role') return 'agent'
  return 'person'
}

const HOW = new Set<ErrorReport['how']>(['error', 'unhandled-rejection', 'boundary'])

/**
 * Builds the report from the list. `body` is whatever the browser sent; the
 * rest is what this server knows for itself.
 */
export function rebuildReport(
  body: unknown,
  known: {
    app: string
    appOrigin: string | undefined
    pubkey: string
    account: AccountKind
    userAgent: string | undefined
    now: number
  },
): ErrorReport {
  const input = (body && typeof body === 'object' ? body : {}) as Record<string, unknown>
  const error = (input.error && typeof input.error === 'object' ? input.error : {}) as Record<
    string,
    unknown
  >

  const frames = (Array.isArray(error.frames) ? error.frames : [])
    .slice(0, MAX_FRAMES)
    .map((frame) => readFrame(frame, known.appOrigin))
    .filter((frame): frame is ReportFrame => frame !== undefined)

  const trail = (Array.isArray(input.trail) ? input.trail : [])
    .slice(-MAX_TRAIL)
    .map((step) => readStep(known.app, step, known.now))
    .filter((step): step is ReportStep => step !== undefined)

  return {
    app: known.app,
    release:
      typeof input.release === 'string' && RELEASE.test(input.release) ? input.release : 'unknown',
    how: HOW.has(input.how as ErrorReport['how']) ? (input.how as ErrorReport['how']) : 'error',
    type: typeof error.type === 'string' && TYPE.test(error.type) ? error.type : 'Error',
    message: scrubMessage(error.message),
    frames,
    screen: readScreen(known.app, input.screen) ?? '<unknown>',
    browser: readBrowser(known.userAgent),
    pubkey: known.pubkey,
    account: known.account,
    trail,
  }
}

/** `client_id=dsn` pairs from `SENTRY_DSNS`, read per call so a test can set it. */
export function sentryDsnFor(clientId: string): string | undefined {
  for (const pair of config().SENTRY_DSNS) {
    const at = pair.indexOf('=')
    if (at > 0 && pair.slice(0, at) === clientId) return pair.slice(at + 1)
  }
  return undefined
}

const MECHANISM: Record<ErrorReport['how'], string> = {
  error: 'onerror',
  'unhandled-rejection': 'onunhandledrejection',
  boundary: 'react.errorboundary',
}

/** The Sentry event: exactly the report's fields, and no request, IP address or extra. */
export function sentryEvent(report: ErrorReport, eventId: string, now: number) {
  return {
    event_id: eventId,
    timestamp: now / 1000,
    platform: 'javascript',
    level: 'error',
    environment: 'production',
    release: report.release,
    transaction: report.screen,
    exception: {
      values: [
        {
          type: report.type,
          value: report.message,
          mechanism: { type: MECHANISM[report.how], handled: false },
          stacktrace: {
            // Sentry reads frames oldest call first; a stack is newest first.
            frames: [...report.frames].reverse().map((frame) => ({
              ...(frame.function ? { function: frame.function } : {}),
              abs_path: frame.absPath,
              filename: frame.absPath,
              ...(frame.line !== undefined ? { lineno: frame.line } : {}),
              ...(frame.column !== undefined ? { colno: frame.column } : {}),
              in_app: frame.absPath !== '<other>',
            })),
          },
        },
      ],
    },
    user: { id: report.pubkey },
    tags: { app: report.app, account: report.account, screen: report.screen },
    contexts: {
      browser: {
        name: report.browser.name,
        ...(report.browser.version ? { version: report.browser.version } : {}),
      },
    },
    breadcrumbs: {
      values: report.trail.map((step) =>
        step.screen
          ? { timestamp: step.at / 1000, category: 'navigation', message: `opened ${step.screen}` }
          : { timestamp: step.at / 1000, category: 'action', message: step.action },
      ),
    },
  }
}

interface ParsedDsn {
  envelopeUrl: string
  publicKey: string
  dsn: string
}

function parseDsn(dsn: string): ParsedDsn | undefined {
  try {
    const url = new URL(dsn)
    const projectId = url.pathname.replace(/^\//, '')
    if (url.protocol !== 'https:' || !url.username || !/^\d+$/.test(projectId)) return undefined
    return {
      envelopeUrl: `https://${url.host}/api/${projectId}/envelope/`,
      publicKey: url.username,
      dsn,
    }
  } catch {
    return undefined
  }
}

/**
 * Sends the report to Sentry's envelope endpoint. Returns whether Sentry took
 * it; a failure is the caller's to log, never the app's to retry.
 */
export async function sendToSentry(
  report: ErrorReport,
  dsn: string,
  now = Date.now(),
): Promise<{ sent: boolean; status?: number; eventId: string }> {
  const eventId = randomBytes(16).toString('hex')
  const target = parseDsn(dsn)
  if (!target) return { sent: false, eventId }

  const body = [
    JSON.stringify({ event_id: eventId, sent_at: new Date(now).toISOString(), dsn: target.dsn }),
    JSON.stringify({ type: 'event' }),
    JSON.stringify(sentryEvent(report, eventId, now)),
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
  return { sent: response.ok, status: response.status, eventId }
}
