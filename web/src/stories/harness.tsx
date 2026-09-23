import type { Decorator } from '@storybook/react-vite'
import { useEffect } from 'react'
/**
 * `?inline` rather than a plain import: the text is injected with the story and
 * removed with it, so the stylesheet is exactly what the real app loads
 * (`main.tsx` imports this file and nothing else) and nothing lingers between
 * stories.
 */
import styles from '../styles.css?inline'

/**
 * The harness Estiva ID's stories run inside.
 *
 * They run in this repo's own Storybook (`pnpm storybook`, :6009 — UIG-36).
 * Until 2026-09-23 they rendered inside Peek's, whose global stylesheet,
 * Tailwind preflight included, was loaded under every story; that is why some
 * screens looked slightly different there. Everything these screens need —
 * their stylesheet, an answer for every request they make, the query string
 * they read — is carried here rather than assumed from the preview.
 */

/** What a story wants `fetch` to answer, keyed by the path `api.ts` requests. */
export type ApiAnswer = unknown | { status: number; body: unknown } | 'pending'
export type ApiRoutes = Record<string, ApiAnswer>

const isEnvelope = (a: ApiAnswer): a is { status: number; body: unknown } =>
  typeof a === 'object' && a !== null && 'status' in a && 'body' in a

/** Scope the account UI's CSS to the stories that are actually its own. */
const withStyles: Decorator = (Story) => {
  // biome-ignore lint/correctness/useExhaustiveDependencies: `styles` is a module import and so looks constant, but Vite replaces the module when styles.css changes — depending on it is what re-injects the stylesheet on hot reload, which is the whole workflow here.
  useEffect(() => {
    const tag = document.createElement('style')
    tag.dataset.estivaId = 'account-ui'
    tag.textContent = styles
    document.head.append(tag)
    return () => tag.remove()
  }, [styles])
  return <Story />
}

/**
 * Answer from fixtures instead of the network.
 *
 * `SecurityCard`, `AdminPeople` and `AuditLog` all call the service on mount, so
 * without this they render an error card rather than a design. Stubbing `fetch`
 * rather than mocking `api.ts` leaves that module doing its real work — error
 * envelope parsing and `ApiError` mapping included — which is why refusal states
 * can be reached at all.
 *
 * Assigned in the decorator body, which React runs before any child effect, so
 * the stub is in place before the first request goes out.
 */
const withApi: Decorator = (Story, context) => {
  const routes = (context.parameters.api ?? {}) as ApiRoutes

  window.fetch = (async (input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
    const path = raw.startsWith('http') ? new URL(raw).pathname + new URL(raw).search : raw
    const key = Object.keys(routes).find((r) => path === r || path.startsWith(`${r}?`))
    const answer = key ? routes[key] : undefined

    // Never resolves: how a loading state holds still long enough to look at.
    if (answer === 'pending') return new Promise<Response>(() => {})

    if (answer === undefined) {
      // Loud on purpose. A screen quietly showing its error state because a
      // story forgot a route is the failure this file exists to prevent.
      const body = { error: { code: 'not_found', message: `No story fixture for ${path}` } }
      return new Response(JSON.stringify(body), { status: 404 })
    }

    const { status, body } = isEnvelope(answer) ? answer : { status: 200, body: answer }
    return new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    })
  }) as typeof fetch

  return <Story />
}

/**
 * The address bar is an input to these screens.
 *
 * `SignIn` reads `?invite=` and `?recovery=` once, as its state initialises, and
 * `App` reads `?next=`. Enrolment and recovery are not reachable any other way,
 * so a story declares the query it wants and gets the screen that produces.
 */
const withLocation: Decorator = (Story, context) => {
  const path = (context.parameters.path ?? window.location.pathname) as string
  const search = (context.parameters.search ?? '') as string
  const target = `${path}${search}`
  if (`${window.location.pathname}${window.location.search}` !== target) {
    window.history.replaceState({}, '', target)
  }
  return <Story />
}

/** Put this on every Estiva ID story's `meta.decorators`. */
export const estivaId: Decorator[] = [withStyles, withApi, withLocation]

/**
 * Pin every Estiva ID story to the Estiva ID theme.
 *
 * The shared Storybook defaults to Signal, which is Peek's dark palette and
 * emphatically not what these screens are. `forceTheme` overrides the toolbar
 * for exactly these stories, so switching the toolbar to compare Peek's themes
 * never silently repaints the account UI into one it does not have.
 */
export const estivaIdParameters = { forceTheme: 'estiva-id' } as const
