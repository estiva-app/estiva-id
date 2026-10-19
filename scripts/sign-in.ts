/**
 * A script's sign-in, the way an app's goes (record sign-in-is-plain-oauth):
 * `/authorize` with the session cookie, then the code and its PKCE verifier
 * redeemed at `/token` in the standard form format. A session cookie alone buys
 * no token.
 *
 * The redirect URI is only matched, never followed, but it must be one
 * registered for the app. The production ones are below; against any other
 * server set `REDIRECT_URI` to one registered there (`PEEK_REDIRECT_URIS` and
 * its siblings).
 */
import { createHash, randomBytes } from 'node:crypto'

const PRODUCTION_REDIRECTS: Record<string, string> = {
  'estiva-peek': 'https://peek.estiva.app/auth/callback',
  'estiva-ship': 'https://ship.estiva.app/',
  'estiva-leaf': 'https://leaf.estiva.app/',
}

export interface SignedIn {
  access_token: string
  refresh_token?: string
  expires_in: number
  pubkey: string
}

export async function signIn(idBase: string, cookie: string, clientId: string): Promise<SignedIn> {
  const redirectUri = process.env.REDIRECT_URI ?? PRODUCTION_REDIRECTS[clientId]
  if (!redirectUri) throw new Error(`set REDIRECT_URI to one registered for ${clientId}`)

  const verifier = randomBytes(32).toString('base64url')
  const authorizeUrl = new URL('/authorize', idBase)
  authorizeUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: 'code',
    code_challenge: createHash('sha256').update(verifier, 'utf8').digest('base64url'),
    code_challenge_method: 'S256',
  }).toString()
  const authorized = await fetch(authorizeUrl, { headers: { cookie }, redirect: 'manual' })
  const location = authorized.headers.get('location') ?? ''
  const code = new URL(location, idBase).searchParams.get('code')
  if (!code)
    throw new Error(`authorize ${authorized.status}: no code in ${location || 'no redirect'}`)

  const response = await fetch(new URL('/token', idBase), {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      code_verifier: verifier,
    }),
  })
  if (!response.ok) throw new Error(`token ${response.status}: ${await response.text()}`)
  return (await response.json()) as SignedIn
}
