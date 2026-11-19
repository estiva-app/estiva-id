/**
 * Estiva ID's server reports its own errors to Sentry (PROD-6), built from the
 * same fixed list as an app's report (`error-reports.ts`).
 *
 * A server error is a fault, not a refusal: an `AppError` (a bad token, a
 * missing passkey) is the caller's answer and is never reported. What a report
 * holds is the error's type, its wording with quoted text removed, the frames
 * of our own files, the route's pattern (never its path, query, headers, body
 * or cookie), the release, and who was signed in, only when the request had
 * already proven it. Nothing else of the request is read.
 *
 * Any request can reach a fault, so the ceilings below keep a loop, or a
 * stranger repeating one request, from spending the month's 5,000 errors.
 * why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/error-reports-go-to-hosted-sentry-built-from-an-allowed-list.md
 */
import { basename, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRateLimiter } from '../http/rate-limit.js'
import type { Logger } from '../logger.js'
import {
  type AccountKind,
  type ErrorReport,
  FUNCTION_NAME,
  RELEASE,
  type ReportFrame,
  TYPE,
  accountKind,
  scrubMessage,
  sendToSentry,
  sentryDsnFor,
} from './error-reports.js'
import { getActivePubkey } from './keys.js'

/** The server, as Sentry and `SENTRY_DSNS` name it. */
export const ESTIVA_ID_SERVER = 'estiva-id-server'

/** `dist/` in the image, `src/` under the tests: only frames under it are ours. */
const ROOT = fileURLToPath(new URL('../', import.meta.url))
const ROOT_NAME = basename(ROOT)
const OWN_FILE = /^[A-Za-z0-9_./-]{1,200}\.(?:m?js|ts)$/
const MAX_FRAMES = 50

/** A route as Hono names it (`POST /admin/people/:id`): written by us, never a person's words. */
const ROUTE = /^[A-Z]{3,7} [A-Za-z0-9_/:*.-]{1,120}$/

// One kind of error a handful of times an hour; every kind together, a few
// dozen a day at most. Per process, so a restart starts them again.
const PER_KIND_PER_HOUR = 3
const ALL_PER_HOUR = 10
const ALL_PER_DAY = 50
const perKind = createRateLimiter(PER_KIND_PER_HOUR, 60 * 60_000)
const allHour = createRateLimiter(ALL_PER_HOUR, 60 * 60_000)
const allDay = createRateLimiter(ALL_PER_DAY, 24 * 60 * 60_000)

/** `    at fn (file:///app/dist/x.js:1:2)` or `    at file:///app/dist/x.js:1:2`. */
const STACK_LINE = /^\s*at (?:(.+?) \((.+):(\d+):(\d+)\)|(.+):(\d+):(\d+))$/

/**
 * Frames of our own files, newest first, as a stack lists them. A frame in a
 * dependency or in Node itself keeps no name or place: it is not our code.
 */
export function serverFrames(stack: string | undefined): ReportFrame[] {
  const frames: ReportFrame[] = []
  for (const line of (stack ?? '').split('\n').slice(1)) {
    if (frames.length >= MAX_FRAMES) break
    const match = STACK_LINE.exec(line)
    if (!match) continue
    const fn = match[1]
    const location = match[2] ?? match[5] ?? ''
    const lineNo = Number(match[3] ?? match[6])
    const column = Number(match[4] ?? match[7])
    let path = location
    if (path.startsWith('file://')) {
      try {
        path = fileURLToPath(path)
      } catch {
        path = ''
      }
    }
    const relative = path.startsWith(ROOT) ? path.slice(ROOT.length).split(sep).join('/') : ''
    if (!relative || relative.includes('node_modules') || !OWN_FILE.test(relative)) {
      frames.push({ absPath: '<other>' })
      continue
    }
    frames.push({
      ...(fn && FUNCTION_NAME.test(fn) ? { function: fn } : {}),
      absPath: `${ROOT_NAME}/${relative}`,
      line: lineNo,
      column,
    })
  }
  return frames
}

export interface ServerErrorContext {
  how: 'error' | 'unhandled-rejection' | 'uncaught-exception'
  /** The route's method and pattern, when a request was being answered. */
  route?: string
  /** Who was signed in, when the request had already proven it. */
  as?: { pubkey: string; account: AccountKind }
}

/** The report, from the list alone. */
export function serverReport(error: unknown, context: ServerErrorContext): ErrorReport {
  const e = error instanceof Error ? error : undefined
  const release = process.env.RELEASE
  return {
    app: ESTIVA_ID_SERVER,
    release: release && RELEASE.test(release) ? release : 'unknown',
    how: context.how,
    type: e && TYPE.test(e.name) ? e.name : e ? 'Error' : 'NonError',
    message: scrubMessage(e?.message),
    frames: serverFrames(e?.stack),
    screen: context.route && ROUTE.test(context.route) ? context.route : '<none>',
    runtime: { name: 'node', version: process.versions.node.split('.')[0] },
    ...(context.as ? { pubkey: context.as.pubkey, account: context.as.account } : {}),
    trail: [],
  }
}

/** Whether the ceilings let one more of this kind through; spends from them when they do. */
function spend(report: ErrorReport): boolean {
  const top = report.frames.find((frame) => frame.absPath !== '<other>')
  const kind = top
    ? `${report.type}@${top.absPath}:${top.line}`
    : `${report.type}:${report.message}`
  return perKind.check(kind).allowed && allHour.check('all').allowed && allDay.check('all').allowed
}

/** Who a session belongs to, for the report; nothing when it cannot be told. */
export async function signedInAs(
  userId: string,
  delegated: boolean,
): Promise<ServerErrorContext['as']> {
  const pubkey = await getActivePubkey(userId)
  return pubkey ? { pubkey, account: await accountKind(pubkey, delegated) } : undefined
}

/**
 * Sends the report, if the ceilings allow and a DSN is set. Never throws: a
 * report that cannot be sent is logged and dropped, and never retried.
 * `context.as` may be a promise, so a caller answering a request need not wait.
 */
export async function reportServerError(
  error: unknown,
  context: Omit<ServerErrorContext, 'as'> & {
    as?: ServerErrorContext['as'] | Promise<ServerErrorContext['as']>
  },
  log: Logger,
): Promise<void> {
  // Caught first, so a failed lookup never becomes an unhandled rejection of its own.
  const signedIn = Promise.resolve(context.as).catch(() => undefined)
  try {
    const dsn = sentryDsnFor(ESTIVA_ID_SERVER)
    if (!dsn) return
    const as = await signedIn
    const report = serverReport(error, { ...context, as })
    if (!spend(report)) return
    const result = await sendToSentry(report, dsn)
    if (!result.sent) log.warn({ status: result.status }, 'sentry refused a server report')
  } catch (failure) {
    log.warn({ err: (failure as Error)?.name }, 'server report not sent')
  }
}
