/**
 * PEEK-90 acceptance: an app on another origin can get a token, and the ways
 * that could go wrong do not.
 *
 * The flow's value is entirely in its refusals. A code that redeems twice, a
 * verifier that is not checked, a redirect URI that is honoured without being
 * registered — each turns the identity provider into the thing it exists to
 * prevent, and none of them are visible from a successful happy path.
 */
import { createHash, randomBytes } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

const REDIRECT = 'https://ship.test/callback'
const CLIENT = 'estiva-ship'

/** A real PKCE pair: verifier, and base64url(sha256(verifier)). */
function pkce() {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url')
  return { verifier, challenge }
}

function authorizeUrl(overrides: Record<string, string> = {}, challenge = pkce().challenge) {
  const params = new URLSearchParams({
    client_id: CLIENT,
    redirect_uri: REDIRECT,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'opaque-state',
    ...overrides,
  })
  return `/authorize?${params.toString()}`
}

const authorize = (url: string, cookie?: string) =>
  app.request(url, { headers: cookie ? { cookie } : {} })

const exchange = (body: Record<string, unknown>) =>
  app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  })

async function auditFor(action: string) {
  const rows = await query<{ outcome: string; detail: Record<string, unknown> }>(
    'select outcome, detail from audit_events where action = $1 order by id',
    [action],
  )
  return rows.rows
}

let ada: Awaited<ReturnType<typeof createUserWithKey>>
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
  cookie = `estiva_id_session=${session.token}`
})

afterAll(async () => {
  await closePool()
})

describe('GET /authorize', () => {
  it('sends an authenticated person back with a code and their state', async () => {
    const response = await authorize(authorizeUrl(), cookie)
    expect(response.status).toBe(302)

    const target = new URL(response.headers.get('location') ?? '')
    expect(`${target.origin}${target.pathname}`).toBe(REDIRECT)
    expect(target.searchParams.get('code')).toMatch(/^[A-Za-z0-9\-_]+$/)
    expect(target.searchParams.get('state')).toBe('opaque-state')
  })

  /**
   * The one that turns an identity provider into an open redirector. Refusing
   * here rather than bouncing is the whole point: the payload would be a code.
   */
  it('refuses an unregistered redirect_uri without redirecting to it', async () => {
    const response = await authorize(
      authorizeUrl({ redirect_uri: 'https://attacker.test/callback' }),
      cookie,
    )
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
  })

  it('refuses an unknown app without redirecting', async () => {
    const response = await authorize(authorizeUrl({ client_id: 'not-an-app' }), cookie)
    expect(response.status).toBe(400)
    expect(response.headers.get('location')).toBeNull()
  })

  // `plain` is in RFC 7636 and protects nothing an interceptor cannot replay.
  it('refuses code_challenge_method=plain', async () => {
    const response = await authorize(authorizeUrl({ code_challenge_method: 'plain' }), cookie)
    expect(response.status).toBe(400)
  })

  /**
   * A client that forgot to hash sends its verifier as the challenge. That
   * "works" — only that client can complete the flow — so it looks like PKCE
   * while providing none of it. The length check is what catches it.
   */
  it('refuses a challenge that is not a base64url SHA-256', async () => {
    const response = await authorize(authorizeUrl({}, 'too-short'), cookie)
    expect(response.status).toBe(400)
  })

  it('sends an unauthenticated person to sign in, remembering where to return', async () => {
    const response = await authorize(authorizeUrl())
    expect(response.status).toBe(302)

    const location = response.headers.get('location') ?? ''
    expect(location.startsWith('/?next=')).toBe(true)
    // Relative only — `next` is attacker-influenced, and an open redirect here
    // would undo the allowlisting above.
    const next = decodeURIComponent(location.slice('/?next='.length))
    expect(next.startsWith('/authorize?')).toBe(true)
  })

  it('sends an inactive identity back to the app as access_denied', async () => {
    await query("update users set status = 'offboarded' where id = $1", [ada.id])

    const response = await authorize(authorizeUrl(), cookie)
    expect(response.status).toBe(302)
    const target = new URL(response.headers.get('location') ?? '')
    expect(target.searchParams.get('error')).toBe('access_denied')
    expect(target.searchParams.get('state')).toBe('opaque-state')
    expect(target.searchParams.get('code')).toBeNull()
  })
})

describe('the authorization_code grant', () => {
  /** Run the browser half and return the code plus its verifier. */
  async function getCode() {
    const { verifier, challenge } = pkce()
    const response = await authorize(authorizeUrl({}, challenge), cookie)
    const code = new URL(response.headers.get('location') ?? '').searchParams.get('code')
    return { code: code as string, verifier }
  }

  const validBody = (code: string, codeVerifier: string) => ({
    grantType: 'authorization_code',
    code,
    clientId: CLIENT,
    redirectUri: REDIRECT,
    codeVerifier,
  })

  it('exchanges a code for a token bound to the right pubkey', async () => {
    const { code, verifier } = await getCode()

    const response = await exchange(validBody(code, verifier))
    expect(response.status).toBe(200)

    const body = (await response.json()) as { access_token: string; pubkey: string }
    expect(body.pubkey).toBe(ada.pubkey)
    expect(body.access_token.split('.')).toHaveLength(3)
  })

  it('refuses the wrong verifier', async () => {
    const { code } = await getCode()
    const response = await exchange(validBody(code, pkce().verifier))
    expect(response.status).toBe(400)
  })

  /**
   * Single use is what makes a stolen code worthless once the real app has
   * redeemed it. The reply is generic; the audit log is specific, because a
   * replay is worth noticing and a caller does not need to be told.
   */
  it('refuses a replayed code, and records it as a replay', async () => {
    const { code, verifier } = await getCode()

    expect((await exchange(validBody(code, verifier))).status).toBe(200)
    expect((await exchange(validBody(code, verifier))).status).toBe(400)

    const refused = (await auditFor('token.exchange')).filter((r) => r.outcome === 'refused')
    expect(refused).toHaveLength(1)
    expect(refused[0]?.detail.reason).toBe('already_used')
  })

  // A failed attempt burns the code too: one that has been presented has been
  // in the wild, and leaving it live invites retrying verifiers against it.
  it('burns a code even when the verifier was wrong', async () => {
    const { code, verifier } = await getCode()

    expect((await exchange(validBody(code, pkce().verifier))).status).toBe(400)
    expect((await exchange(validBody(code, verifier))).status).toBe(400)
  })

  it('refuses a code redeemed against a different redirect_uri', async () => {
    const { code, verifier } = await getCode()
    const response = await exchange({
      ...validBody(code, verifier),
      redirectUri: 'https://ship.test/other',
    })
    expect(response.status).toBe(400)
  })

  it('refuses a code redeemed by a different app', async () => {
    const { code, verifier } = await getCode()
    const response = await exchange({ ...validBody(code, verifier), clientId: 'estiva-peek' })
    expect(response.status).toBe(400)
  })

  it('refuses an expired code', async () => {
    const { code, verifier } = await getCode()
    await query("update authorization_codes set expires_at = now() - interval '1 second'")

    expect((await exchange(validBody(code, verifier))).status).toBe(400)
    const refused = (await auditFor('token.exchange')).filter((r) => r.outcome === 'refused')
    expect(refused[0]?.detail.reason).toBe('expired')
  })

  it('refuses an unknown code', async () => {
    const response = await exchange(
      validBody(randomBytes(32).toString('base64url'), 'x'.repeat(43)),
    )
    expect(response.status).toBe(400)
  })

  // Offboarding has to take effect inside the JWT TTL. A code issued a minute
  // ago is not evidence that the person is still employed.
  it('refuses when the identity was deactivated between the two halves', async () => {
    const { code, verifier } = await getCode()
    await query("update users set status = 'offboarded' where id = $1", [ada.id])

    expect((await exchange(validBody(code, verifier))).status).toBe(403)
  })

  it('needs no cookie — that is the entire point', async () => {
    const { code, verifier } = await getCode()
    const response = await exchange(validBody(code, verifier))
    expect(response.status).toBe(200)
  })
})

describe('the session grant still works', () => {
  it('issues a token to the account page without any redirect dance', async () => {
    const response = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ clientId: CLIENT }),
    })
    expect(response.status).toBe(200)
    expect(((await response.json()) as { pubkey: string }).pubkey).toBe(ada.pubkey)
  })

  it('still refuses without a session', async () => {
    const response = await exchange({ clientId: CLIENT })
    expect(response.status).toBe(401)
  })
})

describe('discovery', () => {
  it('advertises the code flow and S256 only', async () => {
    const document = (await (await app.request('/.well-known/openid-configuration')).json()) as {
      authorization_endpoint: string
      grant_types_supported: string[]
      code_challenge_methods_supported: string[]
    }
    expect(document.authorization_endpoint).toMatch(/\/authorize$/)
    expect(document.grant_types_supported).toContain('authorization_code')
    expect(document.code_challenge_methods_supported).toEqual(['S256'])
  })
})

/**
 * CORS on `/token`, which the code grant cannot work without.
 *
 * The first cross-origin attempt died at the preflight: the redirect completed,
 * the code came back, and the browser refused to let the app read the token.
 * PKCE removes the need for the *cookie* to cross origins, not the need for the
 * response to be readable.
 *
 * The safety argument is the absent header rather than a present one — without
 * `Access-Control-Allow-Credentials` a browser will neither attach the session
 * cookie cross-origin nor expose a credentialed response, so the session grant
 * stays same-origin while the code grant works.
 */
describe('CORS on /token', () => {
  const ORIGIN = 'https://ship.test'

  it('lets a registered origin preflight', async () => {
    const response = await app.request('/token', {
      method: 'OPTIONS',
      headers: { origin: ORIGIN, 'access-control-request-method': 'POST' },
    })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(response.headers.get('vary')).toBe('Origin')
  })

  // The header that would let another origin ride the session cookie.
  it('never allows credentials', async () => {
    const response = await app.request('/token', {
      method: 'OPTIONS',
      headers: { origin: ORIGIN, 'access-control-request-method': 'POST' },
    })
    expect(response.headers.get('access-control-allow-credentials')).toBeNull()
  })

  it('refuses an origin that is not a registered redirect target', async () => {
    const response = await app.request('/token', {
      method: 'OPTIONS',
      headers: { origin: 'https://attacker.test', 'access-control-request-method': 'POST' },
    })
    expect(response.status).toBe(403)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })

  // `https://ship.test` must not authorise `https://ship.test.attacker.example`.
  it('does not let a prefix of a registered origin through', async () => {
    const response = await app.request('/token', {
      method: 'OPTIONS',
      headers: {
        origin: 'https://ship.test.attacker.example',
        'access-control-request-method': 'POST',
      },
    })
    expect(response.status).toBe(403)
  })

  it('echoes the origin on a real exchange', async () => {
    const response = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({
        grantType: 'authorization_code',
        code: 'nope',
        clientId: CLIENT,
        redirectUri: REDIRECT,
        codeVerifier: 'x'.repeat(43),
      }),
    })
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
  })
})
