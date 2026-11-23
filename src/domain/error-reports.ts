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
import { scrubMessage } from './scrub-message.js'

export { scrubMessage }

/**
 * Estiva ID's own pages, as Sentry and `SENTRY_DSNS` name them. Not an OAuth
 * client: its reports are signed in by the session cookie, or come through the
 * signed-out door (`http/routes/report.ts`).
 */
export const ESTIVA_ID_WEB = 'estiva-id-web'

/**
 * Who sent it, by the sign-in: a person, a QA account, or an agent; or nobody
 * yet, for a crash on Estiva ID's own pages before sign-in (PROD-4).
 */
export type AccountKind = 'person' | 'qa' | 'agent' | 'signed-out'

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
  /** `uncaught-exception` is the server's own (PROD-6): no browser can send it. */
  how: 'error' | 'unhandled-rejection' | 'uncaught-exception' | 'boundary' | 'failure' | 'refused'
  /** A failure's name from {@link FAILURES}, or a refusal's code; only on those two. */
  named?: string
  /** Why a failure happened, from {@link FAILURE_REASONS}; only on a failure, absent when the app heard none. */
  reason?: string
  type: string
  message: string
  frames: ReportFrame[]
  screen: string
  /** A browser's report: the browser, from its User-Agent. */
  browser?: Software
  /** The server's own report (PROD-6): Node and its version, in place of a browser. */
  runtime?: Software
  /** Absent before sign-in on Estiva ID's own pages, and on a server error no sign-in had reached. */
  pubkey?: string
  /** Absent only on a server error no sign-in had reached. */
  account?: AccountKind
  trail: ReportStep[]
}

export interface Software {
  name: string
  version?: string
}

const MAX_FRAMES = 50
const MAX_TRAIL = 10
const TRAIL_MAX_AGE_MS = 24 * 60 * 60 * 1000

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
  // Ship and Leaf name a screen by their router's page name: their addresses hold titles (PROD-4).
  'estiva-ship': new Set([
    'elsewhere',
    'folder',
    'inbound',
    'issue',
    'issues',
    'project',
    'projects',
    'topic',
    'topics',
  ]),
  'estiva-leaf': new Set(['document', 'file', 'home', 'path', 'topic', 'topics']),
  // Estiva ID's own pages (`web/`): the account page, sign-in, and a bot's approval.
  [ESTIVA_ID_WEB]: new Set(['/', '/device']),
}

/**
 * Our own named actions, the only words a step may carry besides a screen
 * (Decided: "kinds of screen and our own named actions only"). Adding one is
 * a change to the list, reviewed as one.
 */
const ACTIONS: ReadonlySet<string> = new Set(['sent-message', 'write-refused'])

/**
 * What failed, when an app told a person something failed (PROD-5), with the
 * sentence Sentry shows for it. The message the person saw is never sent: most
 * name a title, a person or the relay's own sentence. `@estiva-app/platform`'s
 * `FAILURES` is the same list; a name not here is `unnamed`.
 */
const FAILURES: ReadonlyMap<string, string> = new Map([
  ['not-sent', 'Not sent'],
  ['not-saved', 'Not saved'],
  ['not-deleted', 'Not deleted'],
  ['not-moved', 'Not moved'],
  ['not-joined', 'Could not join'],
  ['not-left', 'Could not leave'],
  ['not-added', 'Could not add someone'],
  ['not-created', 'Not created'],
  ['not-archived', 'Not archived'],
  ['not-restored', 'Not restored'],
  ['not-renamed', 'Not renamed'],
  ['not-resolved', 'Not resolved'],
  ['not-loaded', 'Could not load'],
  ['not-reached', 'Could not reach the server'],
  ['not-signed', 'Estiva ID would not sign it'],
  ['signed-out', 'The sign-in ended'],
  ['sign-in-failed', 'Could not sign in'],
  ['link-not-valid', 'The link is not valid'],
  ['not-approved', 'The device was not approved'],
  ['unnamed', 'A failure the app showed'],
])

/**
 * Why a failure happened, with the words Sentry shows after the failure's own
 * ("Could not load — the relay said wait"). `@estiva-app/platform`'s
 * `FAILURE_REASONS` is the same list; a reason not here is dropped, and the
 * failure is then filed as one that named none. Each reason of a failure is
 * its own error in Sentry: 23 Nov, nine "Could not load" reports after the
 * per-minute fixes sat in one error and none was the limit.
 *
 * why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/error-reports-go-to-hosted-sentry-built-from-an-allowed-list.md
 */
const FAILURE_REASONS: ReadonlyMap<string, string> = new Map([
  ['told-to-wait', 'the relay said wait'],
  ['id-told-to-wait', 'Estiva ID said wait'],
  ['relay-busy', 'the relay was busy'],
  ['signed-out', 'the sign-in had ended'],
  ['not-reached', 'the server was not reached'],
  ['no-access', 'the relay refused the read'],
  ['other', 'another reason'],
])

/**
 * A refused write's code, as the relay client reads it (`archived`, `busy`,
 * `blocked`, `http-500`); anything else is `uncoded`. Never the relay's sentence.
 * why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/a-refusal-starts-with-a-reason-code-every-app-reads.md
 */
const CODE = /^[a-z][a-z0-9-]{0,39}$/

/** A route pattern the app is known to have: `/app/teams/:id`, never an address. */
export function readScreen(app: string, raw: unknown): string | undefined {
  return typeof raw === 'string' && SCREENS[app]?.has(raw) ? raw : undefined
}

/** A function as a stack names it: `parseBody`, `Object.<anonymous>`, `new Foo`, `async run`. */
export const FUNCTION_NAME =
  /^(?:new |async )?[A-Za-z_$<][\w$<>]{0,60}(?:\.[A-Za-z_$<][\w$<>]{0,60}){0,4}$/
const ASSET_PATH = /^\/assets\/[A-Za-z0-9_.-]{1,100}\.m?js$/
export const RELEASE = /^[0-9a-f]{7,40}$/
export const TYPE = /^[A-Za-z_$][A-Za-z0-9_$]{0,63}$/

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
export function readBrowser(userAgent: string | undefined): Software {
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

const HOW = new Set<ErrorReport['how']>([
  'error',
  'unhandled-rejection',
  'boundary',
  'failure',
  'refused',
])

/** A failure or a refusal carries its name and nothing else: no wording, no frames. */
function readHandled(how: 'failure' | 'refused', named: unknown, why?: unknown) {
  if (how === 'failure') {
    const name = typeof named === 'string' && FAILURES.has(named) ? named : 'unnamed'
    // A failure's reason is one of ours or nothing: never a refusal's, never the app's wording.
    const reason = typeof why === 'string' && FAILURE_REASONS.has(why) ? why : undefined
    const sentence = FAILURES.get(name) as string
    return {
      named: name,
      ...(reason ? { reason } : {}),
      type: 'Failure',
      message: reason ? `${sentence} — ${FAILURE_REASONS.get(reason) as string}` : sentence,
    }
  }
  const code = typeof named === 'string' && CODE.test(named) ? named : 'uncoded'
  return { named: code, type: 'WriteRefused', message: code }
}

/**
 * Builds the report from the list. `body` is whatever the browser sent; the
 * rest is what this server knows for itself.
 */
export function rebuildReport(
  body: unknown,
  known: {
    app: string
    appOrigin: string | undefined
    pubkey: string | undefined
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

  const how = HOW.has(input.how as ErrorReport['how']) ? (input.how as ErrorReport['how']) : 'error'
  const handled =
    how === 'failure' || how === 'refused' ? readHandled(how, input.named, input.reason) : undefined

  return {
    app: known.app,
    release:
      typeof input.release === 'string' && RELEASE.test(input.release) ? input.release : 'unknown',
    how,
    ...(handled
      ? {
          named: handled.named,
          ...('reason' in handled && handled.reason ? { reason: handled.reason } : {}),
          type: handled.type,
          message: handled.message,
          frames: [],
        }
      : {
          type: typeof error.type === 'string' && TYPE.test(error.type) ? error.type : 'Error',
          message: scrubMessage(error.message),
          frames,
        }),
    screen: readScreen(known.app, input.screen) ?? '<unknown>',
    browser: readBrowser(known.userAgent),
    ...(known.pubkey ? { pubkey: known.pubkey } : {}),
    account: known.account,
    trail,
  }
}

/** The DSN for an app from `client_id=dsn` pairs. */
export function dsnFor(pairs: readonly string[], clientId: string): string | undefined {
  for (const pair of pairs) {
    const at = pair.indexOf('=')
    if (at > 0 && pair.slice(0, at) === clientId) return pair.slice(at + 1)
  }
  return undefined
}

/** `client_id=dsn` pairs from `SENTRY_DSNS`, read per call so a test can set it. */
export function sentryDsnFor(clientId: string): string | undefined {
  return dsnFor(config().SENTRY_DSNS, clientId)
}

const MECHANISM: Record<ErrorReport['how'], string> = {
  error: 'onerror',
  'unhandled-rejection': 'onunhandledrejection',
  'uncaught-exception': 'onuncaughtexception',
  boundary: 'react.errorboundary',
  failure: 'failure-shown',
  refused: 'write-refused',
}

const software = (s: Software) => ({ name: s.name, ...(s.version ? { version: s.version } : {}) })

/**
 * The Sentry event: exactly the report's fields, and no request, IP address or
 * extra. A failure or a refusal is grouped by its name (one issue per app for
 * each code, so expected refusals such as `not-member` stay in their own row),
 * an `unnamed` failure by its screen too, and is marked handled. A failure
 * that says why is grouped by its reason as well; one that says none keeps
 * the grouping it had, so an older tab's reports stay where they were.
 */
export function sentryEvent(report: ErrorReport, eventId: string, now: number) {
  const handled = report.how === 'failure' || report.how === 'refused'
  const fingerprint = [
    report.how,
    report.named ?? '',
    ...(report.named === 'unnamed' ? [report.screen] : []),
    ...(report.reason ? [report.reason] : []),
  ]
  return {
    event_id: eventId,
    ...(handled ? { fingerprint } : {}),
    timestamp: now / 1000,
    platform: report.runtime ? 'node' : 'javascript',
    level: 'error',
    environment: 'production',
    release: report.release,
    transaction: report.screen,
    exception: {
      values: [
        {
          type: report.type,
          value: report.message,
          mechanism: { type: MECHANISM[report.how], handled },
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
    ...(report.pubkey ? { user: { id: report.pubkey } } : {}),
    tags: {
      app: report.app,
      ...(report.account ? { account: report.account } : {}),
      screen: report.screen,
      ...(report.how === 'failure' ? { failure: report.named } : {}),
      ...(report.reason ? { reason: report.reason } : {}),
      ...(report.how === 'refused' ? { code: report.named } : {}),
    },
    contexts: {
      ...(report.browser ? { browser: software(report.browser) } : {}),
      ...(report.runtime ? { runtime: software(report.runtime) } : {}),
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

export function parseDsn(dsn: string): ParsedDsn | undefined {
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
