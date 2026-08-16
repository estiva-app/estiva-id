/**
 * PEEK-122 acceptance: an app can end the session, and cannot be used to end
 * somebody up on an arbitrary origin while doing it.
 *
 * The valuable assertions are the refusals and the idempotence. A logout that
 * redirects wherever it is asked is an open redirector that needs no session to
 * reach, and a logout that `401`s when there is nothing to revoke turns a
 * double-click into an error page.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createSession, resolveSession } from '../../domain/sessions.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

const REDIRECT = 'https://ship.test/callback'
const CLIENT = 'estiva-ship'

function logoutUrl(overrides: Record<string, string> = {}) {
  const params = new URLSearchParams({
    client_id: CLIENT,
    post_logout_redirect_uri: REDIRECT,
    state: 'opaque-state',
    ...overrides,
  })
  return `/logout?${params.toString()}`
}

const logout = (url: string, cookie?: string) =>
  app.request(url, { headers: cookie ? { cookie } : {} })

let ada: Awaited<ReturnType<typeof createUserWithKey>>
let sessionToken: string
let cookie: string

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [REDIRECT],
    CLIENT,
  ])
  ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
  const session = await createSession({ userId: ada.id })
  sessionToken = session.token
  cookie = `estiva_id_session=${session.token}`
})

afterAll(async () => {
  await closePool()
})

describe('GET /logout', () => {
  it('revokes the session and sends the person back to the app', async () => {
    const response = await logout(logoutUrl(), cookie)
    expect(response.status).toBe(302)

    const target = new URL(response.headers.get('location') ?? '')
    expect(target.origin + target.pathname).toBe(REDIRECT)
    expect(target.searchParams.get('state')).toBe('opaque-state')

    // The actual point: the session is gone server-side, so the next silent
    // probe from any app finds nothing.
    expect(await resolveSession(sessionToken)).toBeUndefined()
  })

  it('clears the cookie so the browser stops presenting it', async () => {
    const response = await logout(logoutUrl(), cookie)
    expect(response.headers.get('set-cookie') ?? '').toMatch(/estiva_id_session=/)
  })

  /**
   * The refusal that matters most. This endpoint answers without a session, so
   * an unvalidated `post_logout_redirect_uri` would be an open redirector
   * anybody could reach — worse than `/authorize`'s, which at least needs one.
   */
  it('refuses an unregistered post_logout_redirect_uri rather than redirecting', async () => {
    const response = await logout(
      logoutUrl({ post_logout_redirect_uri: 'https://attacker.test/steal' }),
      cookie,
    )
    expect(response.status).toBe(400)
    // And it did not log anybody out on the way to refusing.
    expect(await resolveSession(sessionToken)).toBeDefined()
  })

  it('refuses an unknown client', async () => {
    const response = await logout(logoutUrl({ client_id: 'not-an-app' }), cookie)
    expect(response.status).toBe(400)
  })

  /**
   * "Make there be no session" is satisfied by there already being none.
   * Refusing would make a double-click, or a bookmarked logout link, an error.
   */
  it('is idempotent — logging out twice is not an error', async () => {
    await logout(logoutUrl(), cookie)
    const second = await logout(logoutUrl(), cookie)
    expect(second.status).toBe(302)
  })

  it('succeeds for a browser that never had a session', async () => {
    const response = await logout(logoutUrl())
    expect(response.status).toBe(302)
    expect(new URL(response.headers.get('location') ?? '').origin).toBe('https://ship.test')
  })

  it('records who was logged out, and how', async () => {
    await logout(logoutUrl(), cookie)
    const rows = await query<{ outcome: string; detail: Record<string, unknown> }>(
      "select outcome, detail from audit_events where action = 'session.revoke' order by id",
    )
    expect(rows.rows).toHaveLength(1)
    expect(rows.rows[0]?.outcome).toBe('success')
    expect(rows.rows[0]?.detail).toMatchObject({ via: 'end_session' })
  })

  it('advertises itself in discovery', async () => {
    const response = await app.request('/.well-known/openid-configuration')
    const document = (await response.json()) as { end_session_endpoint?: string }
    expect(document.end_session_endpoint).toMatch(/\/logout$/)
  })
})
