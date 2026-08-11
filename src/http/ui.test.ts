/**
 * The UI mount must not eat the API (PEEK-68).
 *
 * A catch-all that returns the app shell is the standard SPA arrangement and
 * the standard way to break an API: a mistyped path answers `200 text/html`
 * instead of a JSON `404`, and the caller gets a JSON parse error rather than
 * the error the service meant to send. These tests exist to pin the boundary,
 * because nothing else would notice it moving.
 *
 * They require `pnpm build:web` to have run — CI does it before `pnpm test`
 * for exactly this reason, since the mount is conditional on a build existing.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { createApp } from './app.js'
import { uiIsBuilt } from './ui.js'

const app = createApp()

describe.runIf(uiIsBuilt())('the account UI', () => {
  it('serves the app shell to a browser', async () => {
    const response = await app.request('/', { headers: { accept: 'text/html' } })
    expect(response.status).toBe(200)
    expect(response.headers.get('content-type')).toContain('text/html')
    expect(await response.text()).toContain('<div id="root">')
  })

  it('serves the shell for a client-side route that is not a real path', async () => {
    const response = await app.request('/account/anything', { headers: { accept: 'text/html' } })
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('<div id="root">')
  })

  // The whole point of the accept-header guard.
  it('still answers an unknown API path with a JSON 404', async () => {
    const response = await app.request('/me/does-not-exist')
    expect(response.status).toBe(404)
    expect(await response.json()).toMatchObject({ error: { code: 'not_found' } })
  })

  it('does not shadow a real route that refuses', async () => {
    // No session — this must stay a 401 envelope, not the app shell.
    const response = await app.request('/me')
    expect(response.status).toBe(401)
    expect(await response.json()).toMatchObject({ error: { code: 'unauthenticated' } })
  })

  /**
   * A browser navigating to a signed-out account page sends `accept: text/html`
   * and should get the shell, which then asks `/me` and renders "not signed
   * in". The shell itself is never gated on a session — gating it would mean
   * the page cannot render its own signed-out state.
   */
  it('serves the shell without a session', async () => {
    const response = await app.request('/', { headers: { accept: 'text/html' } })
    expect(response.status).toBe(200)
  })

  /**
   * Every client-side route must reach the app, not an API handler (PEEK-69).
   *
   * The API is mounted *before* the catch-all so a mistyped API path answers a
   * JSON 404 rather than the shell. The cost is that a client route sharing a
   * string with a real endpoint is swallowed by it — `/admin/audit` served the
   * audit JSON to a browser navigating there, which looked like a blank screen
   * and is not something any other test would have noticed. This is the guard.
   */
  it.each(['/admin', '/admin/history', '/admin/0e5b6e8c-1c3f-4c2a-9a7e-2b6a1f0d4c11'])(
    'serves the app shell for the client route %s',
    async (route) => {
      const response = await app.request(route, { headers: { accept: 'text/html' } })
      expect(response.status).toBe(200)
      expect(response.headers.get('content-type')).toContain('text/html')
      expect(await response.text()).toContain('<div id="root">')
    },
  )

  /**
   * And the other direction: the endpoints behind those screens must keep
   * answering JSON to a `fetch`, which sends no `text/html`.
   */
  it.each(['/admin/people', '/admin/audit'])('keeps %s an API path', async (route) => {
    const response = await app.request(route)
    expect(response.headers.get('content-type')).toContain('application/json')
    // Unauthenticated, so a refusal envelope — the point is that it is JSON.
    expect(response.status).toBe(401)
  })

  it('does not let a stale shell be cached for the next person', async () => {
    const response = await app.request('/', { headers: { accept: 'text/html' } })
    expect(response.headers.get('cache-control')).toBe('no-store')
  })
})

/**
 * Every admin write must be reachable from the console (PEEK-65).
 *
 * `POST /invites` existed, was admin-guarded, and was covered by seven route
 * tests — and **nothing in `web/` ever called it**. So the single action the
 * admin console exists for, adding a colleague, could only be performed with
 * curl or over SSH. The people list showed pending invites while offering no
 * way to create one.
 *
 * No server test could have caught that, because the server was correct. Every
 * route test reached for the `createInvite` *domain function* or posted the
 * path directly, which is precisely the blind spot: both prove the endpoint
 * works and neither proves anybody can get to it.
 *
 * So this checks the seam between the two halves rather than either half. It is
 * deliberately structural — matching path literals, not behaviour — because the
 * failure it guards against is an endpoint with no caller, and that is visible
 * in the text.
 */
describe('the console can reach every admin write', () => {
  // Read from disk rather than listed, so a new route file is covered the day
  // it lands instead of the day somebody remembers to add it here.
  const routesDir = new URL('routes/', import.meta.url)
  const routeSources = readdirSync(routesDir).filter(
    (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
  )

  /** Admin-guarded mutations, read out of the route files rather than listed. */
  function adminWrites(source: string): { path: string; method: string }[] {
    const found: { path: string; method: string }[] = []
    // `routes.post('/path', ...adminOnly, …)` — the guard has to be on the same
    // line as the path, which is how every route in this service is written.
    const pattern = /routes\.(post|put|delete)\(\s*'([^']+)'\s*,\s*\.\.\.adminOnly/g
    let match = pattern.exec(source)
    while (match !== null) {
      found.push({ method: (match[1] as string).toUpperCase(), path: match[2] as string })
      match = pattern.exec(source)
    }
    return found
  }

  const client = readFileSync(new URL('../../web/src/api.ts', import.meta.url), 'utf8')

  const writes = routeSources.flatMap((file) =>
    adminWrites(readFileSync(new URL(file, routesDir), 'utf8')).map(
      (write) => [file, write.path, write.method] as const,
    ),
  )

  // A guard that silently matched nothing would pass forever.
  it('found the admin writes to check', () => {
    expect(writes.length).toBeGreaterThan(3)
  })

  it.each(writes)('%s exposes %s (%s) to the client', (_file, path, method) => {
    /*
      Matched on path *and* method together, which the first version of this
      test got wrong: `/invites` also appears in the client's `getInvite`, so a
      bare substring check passed while the POST had no caller at all — the very
      bug being guarded against, surviving its own guard.

      The last static segment is the distinguishing one (`/offboard`,
      `/reinstate`, `/invites`), and the client writes its method within a few
      lines of the path, so a window after the match is enough without parsing
      TypeScript. Compared by literal segments because the client builds these
      as template strings: `/admin/people/${id}/offboard`.
    */
    const segments = path.split(/:[a-zA-Z]+/).filter((part) => part !== '' && part !== '/')
    const distinguishing = segments[segments.length - 1] as string

    const callers: string[] = []
    for (let at = client.indexOf(distinguishing); at !== -1; ) {
      callers.push(client.slice(at, at + 220))
      at = client.indexOf(distinguishing, at + 1)
    }

    expect(callers.length, `${path} appears nowhere in web/src/api.ts`).toBeGreaterThan(0)
    expect(
      callers.some((caller) => caller.includes(`method: '${method}'`)),
      `${method} ${path} has no caller in web/src/api.ts — the endpoint exists but no screen can reach it`,
    ).toBe(true)
  })
})
