/**
 * Estiva ID's own crash reports (PROD-4): when a part of these pages breaks,
 * you see "Something went wrong … try again" instead of a blank page, and a
 * short report goes to this server's `/report`, on to Sentry.
 *
 * The apps use `@estiva-app/platform`'s reporter; this origin holds the signing
 * keys and takes no package it does not need, so it sends the same fields by
 * the same list here, with the server's own wording rules
 * (`src/domain/scrub-message.ts`). Signed in, the session cookie says who;
 * before sign-in the server takes it through its signed-out door.
 *
 * Never sent: a page's address or query (a sign-in or recovery code), what was
 * typed, or an error's quoted wording. The screen is the path's pattern only.
 */
import { Component, type ReactNode, useEffect, useState } from 'react'
import { scrubMessage } from '../../src/domain/scrub-message'

/** The pages this origin draws; anything else is sent as `<unknown>`. The server keeps the same list. */
const SCREENS = ['/', '/device'] as const

type How = 'error' | 'unhandled-rejection' | 'boundary'
interface Frame {
  function?: string
  file: string
  line?: number
  column?: number
}

const RELEASE = String(import.meta.env.VITE_ID_RELEASE ?? 'unknown')
const MAX_PER_TAB = 10
const MAX_FRAMES = 50
const ASSETS = `${window.location.origin}/assets/`

function screenOf(pathname: string): string {
  return (SCREENS as readonly string[]).includes(pathname) ? pathname : '<unknown>'
}

/** The page opened, the one step these pages have. */
const trail = [{ screen: screenOf(window.location.pathname), at: Date.now() }]
const seen = new Set<string>()
let sent = 0

/**
 * A stack's frames that are this origin's own bundles, newest first. Chrome
 * writes `at fn (url:1:2)`; Firefox and Safari `fn@url:1:2`. Any other file is
 * left out here, and again by the server.
 */
function readFrames(stack: unknown): Frame[] {
  if (typeof stack !== 'string') return []
  const frames: Frame[] = []
  for (const line of stack.split('\n')) {
    const match =
      /^\s*at (?:(.+?) \()?(.+?):(\d+):(\d+)\)?$/.exec(line) ??
      /^(.*?)@(.+?):(\d+):(\d+)$/.exec(line)
    if (!match) continue
    const [, fn, url, row, col] = match
    const file = (url ?? '').split(/[?#]/)[0] ?? ''
    if (!file.startsWith(ASSETS)) continue
    frames.push({ ...(fn ? { function: fn } : {}), file, line: Number(row), column: Number(col) })
    if (frames.length === MAX_FRAMES) break
  }
  return frames
}

/** Report an error, once per kind of error per tab and at most ten per tab. Never throws. */
export function reportError(error: unknown, how: How): void {
  try {
    const type = error instanceof Error ? error.name : 'Error'
    const message = scrubMessage(error instanceof Error ? error.message : '')
    const frames = readFrames(error instanceof Error ? error.stack : undefined)
    const kind = `${type}|${message}|${frames[0]?.file ?? ''}:${frames[0]?.line ?? ''}`
    if (seen.has(kind) || sent >= MAX_PER_TAB) return
    seen.add(kind)
    sent++
    const body = JSON.stringify({
      release: RELEASE,
      how,
      error: { type, message, frames },
      screen: screenOf(window.location.pathname),
      trail,
    })
    void fetch('/report', {
      method: 'POST',
      keepalive: true,
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body,
    }).catch(() => {})
  } catch {
    // Reporting a crash must never become a second one.
  }
}

/**
 * What failed, when a page tells the person something failed (PROD-5): the
 * names the server's `FAILURES` list keeps for this origin. The message on
 * the page is never sent: many are the server's own sentence.
 */
export type Failure =
  | 'sign-in-failed'
  | 'link-not-valid'
  | 'not-approved'
  | 'not-saved'
  | 'not-loaded'
  | 'not-reached'
  | 'unnamed'

const handledSeen = new Set<string>()

/**
 * Report that the page told the person something failed, by what failed.
 * Once per name per tab, and at most ten per tab apart from crashes; before
 * sign-in the server's signed-out door limits it again. Never throws.
 */
export function reportFailure(what: Failure): void {
  try {
    if (handledSeen.has(what) || handledSeen.size >= MAX_PER_TAB) return
    handledSeen.add(what)
    const body = JSON.stringify({
      release: RELEASE,
      how: 'failure',
      named: what,
      error: { type: 'Failure', message: what, frames: [] },
      screen: screenOf(window.location.pathname),
      trail,
    })
    void fetch('/report', {
      method: 'POST',
      keepalive: true,
      credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body,
    }).catch(() => {})
  } catch {
    // Reporting a failure must never become one.
  }
}

/** Starts reporting the window's unhandled errors and rejections. */
export function startErrorReports(): void {
  // No error object (a script from another origin, an extension): nothing of ours to report.
  window.addEventListener('error', (event) => {
    if (event.error instanceof Error) reportError(event.error, 'error')
  })
  window.addEventListener('unhandledrejection', (event) =>
    reportError(event.reason, 'unhandled-rejection'),
  )
  window.__crashOnPurpose = crashOnPurpose
}

/**
 * The red notice a page shows when something failed, reported by what failed
 * when it appears ({@link reportFailure}); its text is never sent.
 */
export function ErrorNotice({
  failure,
  as: Tag = 'div',
  children,
}: {
  failure: Failure
  as?: 'div' | 'p'
  children: ReactNode
}) {
  useEffect(() => reportFailure(failure), [failure])
  return <Tag className="notice error">{children}</Tag>
}

/**
 * Keeps a crash inside these pages from leaving a blank page: it shows
 * "Something went wrong … try again", the words the apps' own message uses,
 * and Try again draws the page again. Reports what it caught.
 */
export class ErrorBoundary extends Component<{ children: ReactNode }, { crashed: boolean }> {
  override state = { crashed: false }

  static getDerivedStateFromError() {
    return { crashed: true }
  }

  override componentDidCatch(error: unknown) {
    console.error('page crashed:', error)
    reportError(error, 'boundary')
  }

  override render() {
    if (!this.state.crashed) return this.props.children
    return (
      <div className="page narrow">
        <section className="card">
          <div className="notice error">Something went wrong. Your data is safe — try again.</div>
          <button
            type="button"
            className="primary"
            onClick={() => this.setState({ crashed: false })}
          >
            Try again
          </button>
        </section>
      </div>
    )
  }
}

declare global {
  interface Window {
    /** A crash in these pages' own code, to check a report end to end on production. See {@link crashOnPurpose}. */
    __crashOnPurpose?: typeof crashOnPurpose
  }
}

let crashWith: ((text: string) => void) | undefined

/**
 * `window.__crashOnPurpose(text, how)`: the page reads `text` as JSON and
 * fails, so a report can be checked end to end on production (PROD-4).
 * `'render'` (the default) fails inside the page, which shows the message;
 * `'unhandled'` fails in a timer, which nothing catches.
 *
 * Its crashes are told apart from real ones as a JSON `SyntaxError` breaking
 * in this file, where nothing else parses JSON. The sweep and the process
 * review leave those out of the errors people hit (PROD-3), so keep the
 * failing parse here and no other parse in this file.
 */
function crashOnPurpose(text: string, how: 'render' | 'unhandled' = 'render'): void {
  if (how === 'unhandled') setTimeout(() => JSON.parse(text))
  else crashWith?.(text)
}

/** The part of the page `crashOnPurpose` fails inside; nothing on screen until then. */
export function CrashOnPurpose(): null {
  const [text, setText] = useState<string>()
  useEffect(() => {
    crashWith = setText
    return () => {
      crashWith = undefined
    }
  }, [])
  if (text !== undefined) JSON.parse(text)
  return null
}
