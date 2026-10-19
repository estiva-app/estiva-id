/**
 * Register an identity against a running Estiva ID and print a token.
 *
 * There is no UI yet, so this is the only way to exercise the real path end to
 * end: a genuine WebAuthn registration ceremony, a session cookie, and a JWT —
 * using the same software authenticator the tests drive, which emits real CBOR
 * attestation objects, COSE keys and DER signatures.
 *
 *   ID_BASE=https://id.estiva.app RP_ID=estiva.app \
 *   CLIENT_ID=estiva-peek npx tsx scripts/register-identity.ts
 *
 * **This creates a real user.** The passkey it enrols exists only in this
 * process and is gone when it exits, so the account is unreachable afterwards —
 * useful for verification, useless as an identity. Delete it when finished.
 *
 * `RP_ID` must match the server's, and `ID_BASE` must be one of its
 * `RP_ORIGINS`, or verification fails the way a real browser would.
 */
import { SoftwareAuthenticator } from '../src/test/authenticator.js'
import { signIn } from './sign-in.js'

const ID_BASE = process.env.ID_BASE ?? 'http://localhost:8787'
const RP_ID = process.env.RP_ID ?? 'localhost'
const CLIENT_ID = process.env.CLIENT_ID ?? 'estiva-peek'
const EMAIL = process.env.EMAIL ?? `probe-${Date.now()}@invalid.test`

async function post(path: string, body: unknown, cookie?: string): Promise<Response> {
  return fetch(`${ID_BASE}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  })
}

async function main(): Promise<void> {
  const device = new SoftwareAuthenticator({ rpId: RP_ID, origin: ID_BASE })

  const optionsResponse = await post('/auth/register/options', {
    email: EMAIL,
    displayName: 'Verification probe',
  })
  if (!optionsResponse.ok) {
    throw new Error(`register/options ${optionsResponse.status}: ${await optionsResponse.text()}`)
  }
  const options = (await optionsResponse.json()) as { challenge: string }

  const verifyResponse = await post('/auth/register/verify', device.register(options.challenge))
  if (!verifyResponse.ok) {
    throw new Error(`register/verify ${verifyResponse.status}: ${await verifyResponse.text()}`)
  }
  const verified = (await verifyResponse.json()) as { verified: boolean; pubkey: string }

  const setCookie = verifyResponse.headers.get('set-cookie')
  if (!setCookie) throw new Error('no session cookie returned')
  const cookie = setCookie.split(';')[0] as string

  const token = await signIn(ID_BASE, cookie, CLIENT_ID)

  const result = {
    email: EMAIL,
    pubkey: verified.pubkey,
    expiresIn: token.expires_in,
    accessToken: token.access_token,
  }
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
}

await main()
