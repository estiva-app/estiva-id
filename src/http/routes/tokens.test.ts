/**
 * PEEK-29 acceptance.
 *
 * *"Done when: a token issued here is accepted by a Convex deployment
 * configured against this domain, and `getUserIdentity().subject` is the
 * pubkey."*
 *
 * The Convex half of that cannot run here — it needs a deployed HTTPS origin and
 * a change in another repo. What is proved instead is the flow Convex performs:
 * a relying party that knows **only the issuer URL** discovers the JWKS and
 * validates a token, with `sub` as the pubkey. If this passes, what remains for
 * Stage 2 is configuration, not implementation.
 */
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from 'jose'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()
const cfg = config()

/**
 * A relying party. Knows the issuer URL and an application id, nothing else —
 * exactly what `convex/auth.config.ts` is given.
 */
async function validateAsRelyingParty(token: string, applicationId: string) {
  const discovery = (await (await app.request('/.well-known/openid-configuration')).json()) as {
    issuer: string
    jwks_uri: string
  }

  expect(discovery.issuer).toBe(cfg.ISSUER_URL)

  // Fetch JWKS from the advertised location, not from a path we hardcoded.
  const jwksPath = new URL(discovery.jwks_uri).pathname
  const jwks = (await (await app.request(jwksPath)).json()) as { keys: unknown[] }

  return jwtVerify(token, createLocalJWKSet(jwks as never), {
    issuer: discovery.issuer,
    audience: applicationId,
  })
}

beforeAll(async () => {
  await prepareDatabase()
})
beforeEach(async () => {
  await truncateAll()
})
afterAll(async () => {
  await closePool()
})

describe('discovery', () => {
  it('advertises the issuer and a resolvable JWKS URI', async () => {
    const response = await app.request('/.well-known/openid-configuration')
    expect(response.status).toBe(200)

    const doc = (await response.json()) as Record<string, unknown>
    expect(doc).toMatchObject({
      issuer: cfg.ISSUER_URL,
      jwks_uri: `${cfg.ISSUER_URL}/.well-known/jwks.json`,
      id_token_signing_alg_values_supported: ['ES256'],
    })
  })

  it('serves a public JWKS with no private material', async () => {
    const response = await app.request('/.well-known/jwks.json')
    expect(response.status).toBe(200)

    const body = await response.text()
    const jwks = JSON.parse(body) as { keys: Record<string, unknown>[] }

    expect(jwks.keys).toHaveLength(1)
    expect(jwks.keys[0]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256', use: 'sig' })
    // `d` is the private scalar of an EC JWK. Its presence would be the bug.
    expect(jwks.keys[0]).not.toHaveProperty('d')
    expect(body).not.toContain('"d"')
  })

  it('keeps the same kid across restarts', async () => {
    const first = (await (await app.request('/.well-known/jwks.json')).json()) as {
      keys: { kid: string }[]
    }
    const second = (await (await createApp().request('/.well-known/jwks.json')).json()) as {
      keys: { kid: string }[]
    }
    expect(second.keys[0]?.kid).toBe(first.keys[0]?.kid)
  })
})

describe('token validation by a relying party', () => {
  it('validates a token knowing only the issuer URL, with sub = pubkey', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test' })
    const { token } = await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })

    const { payload } = await validateAsRelyingParty(token, 'estiva-peek')

    // This is the value Convex surfaces as getUserIdentity().subject.
    expect(payload.sub).toBe(ada.pubkey)
    expect(payload.iss).toBe(cfg.ISSUER_URL)
    expect(payload.aud).toBe('estiva-peek')
  })

  it('signs with a kid that discovery actually lists', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test' })
    const { token } = await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })

    const header = decodeProtectedHeader(token)
    const jwks = (await (await app.request('/.well-known/jwks.json')).json()) as {
      keys: { kid: string }[]
    }
    expect(jwks.keys.map((key) => key.kid)).toContain(header.kid)
  })

  // Audience binding is what makes PEEK-71's per-app policy meaningful: a token
  // lifted out of one app must not pass as another app's.
  it('rejects a token presented to the wrong application', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test' })
    const { token } = await issueToken({ pubkey: ada.pubkey, clientId: 'linear-lite' })

    await expect(validateAsRelyingParty(token, 'estiva-peek')).rejects.toThrow()
  })
})

describe('POST /token', () => {
  it('requires a session', async () => {
    const response = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ clientId: 'estiva-peek' }),
    })
    expect(response.status).toBe(401)
  })

  it('refuses to mint a token for an unknown app', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test' })
    const cookie = await sessionFor(ada.id)

    const response = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ clientId: 'not-an-app' }),
    })
    expect(response.status).toBe(403)
  })

  it('exchanges a session for a token a relying party accepts', async () => {
    const ada = await createUserWithKey({ email: 'ada@example.test' })
    const cookie = await sessionFor(ada.id)

    const response = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ clientId: 'estiva-peek' }),
    })
    expect(response.status).toBe(200)

    const body = (await response.json()) as { access_token: string; token_type: string }
    expect(body.token_type).toBe('Bearer')

    const { payload } = await validateAsRelyingParty(body.access_token, 'estiva-peek')
    expect(payload.sub).toBe(ada.pubkey)
  })
})

describe('rotation', () => {
  it('keeps serving a previous key so tokens issued before a rotation still validate', async () => {
    const before = (await (await app.request('/.well-known/jwks.json')).json()) as {
      keys: { kid: string }[]
    }
    const oldKid = before.keys[0]?.kid
    if (!oldKid) throw new Error('expected an active key')

    await query("update jwt_signing_keys set status = 'previous' where kid = $1", [oldKid])

    const after = (await (await app.request('/.well-known/jwks.json')).json()) as {
      keys: { kid: string }[]
    }
    const kids = after.keys.map((key) => key.kid)

    expect(kids).toContain(oldKid)
    expect(kids).toHaveLength(2)
  })
})

/** Open a session directly, bypassing the WebAuthn ceremony covered elsewhere. */
async function sessionFor(userId: string): Promise<string> {
  const { createSession } = await import('../../domain/sessions.js')
  const { token } = await createSession({ userId })
  return `estiva_id_session=${token}`
}
