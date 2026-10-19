/**
 * `/token` as every client now calls it (record sign-in-is-plain-oauth): an
 * `application/x-www-form-urlencoded` body with RFC 6749's parameter names.
 */
import { createHash, randomBytes } from 'node:crypto'
import type { createApp } from '../http/app.js'

type App = ReturnType<typeof createApp>

export async function requestToken(
  app: App,
  params: Record<string, string>,
  headers: Record<string, string> = {},
): Promise<Response> {
  return app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: new URLSearchParams(params).toString(),
  })
}

/**
 * A person's sign-in, the only way from a session to a token: `/authorize`
 * with the session cookie, then the code redeemed with its PKCE verifier. The
 * redirect must be registered for the app.
 */
export async function signIn(
  app: App,
  cookie: string,
  clientId: string,
  redirectUri: string,
): Promise<Response> {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier, 'utf8').digest('base64url')
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  })
  const authorized = await app.request(`/authorize?${params.toString()}`, { headers: { cookie } })
  // Without a live session the redirect is this service's own sign-in page, a
  // relative URL with no code; the exchange then fails as a real app's would.
  const location = new URL(authorized.headers.get('location') ?? '', 'http://estiva-id.test')
  const code = location.searchParams.get('code') ?? ''
  return requestToken(app, {
    grant_type: 'authorization_code',
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  })
}
