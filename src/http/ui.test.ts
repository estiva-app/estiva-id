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

  it('does not let a stale shell be cached for the next person', async () => {
    const response = await app.request('/', { headers: { accept: 'text/html' } })
    expect(response.headers.get('cache-control')).toBe('no-store')
  })
})
