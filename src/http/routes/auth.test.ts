/**
 * PEEK-26 acceptance, driven through real WebAuthn ceremonies.
 *
 * *"Done when: a person can register, sign in from a second device, and
 * list/revoke their own credentials."*
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, queryOne } from '../../db/pool.js'
import { SoftwareAuthenticator } from '../../test/authenticator.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()
const cfg = config()

function authenticator() {
  return new SoftwareAuthenticator({ rpId: cfg.RP_ID, origin: cfg.RP_ORIGINS[0] as string })
}

function sessionCookie(response: Response): string {
  const header = response.headers.get('set-cookie')
  if (!header) throw new Error('expected a session cookie')
  return header.split(';')[0] as string
}

async function post(path: string, body: unknown, cookie?: string): Promise<Response> {
  return app.request(path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify(body ?? {}),
  })
}

/** Register a fresh user and return their cookie, authenticator and pubkey. */
async function register(email: string) {
  const device = authenticator()
  const optionsResponse = await post('/auth/register/options', { email, displayName: 'Test User' })
  expect(optionsResponse.status).toBe(200)
  const options = (await optionsResponse.json()) as { challenge: string }

  const verifyResponse = await post('/auth/register/verify', device.register(options.challenge))
  expect(verifyResponse.status).toBe(200)
  const verified = (await verifyResponse.json()) as { verified: boolean; pubkey: string }

  return { device, cookie: sessionCookie(verifyResponse), pubkey: verified.pubkey }
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

describe('registration', () => {
  it('registers a passkey and opens a session', async () => {
    const { pubkey, cookie } = await register('ada@example.test')

    expect(pubkey).toMatch(/^[0-9a-f]{64}$/)
    expect(cookie).toContain('estiva_id_session=')

    const me = await app.request('/me', { headers: { cookie } })
    expect(me.status).toBe(200)
    await expect(me.json()).resolves.toMatchObject({
      email: 'ada@example.test',
      status: 'active',
      pubkey,
    })
  })

  // PEEK-27: a user cannot exist without a key, and the key is minted at
  // creation rather than on first use.
  it('mints exactly one active custodied key at registration', async () => {
    const { pubkey } = await register('grace@example.test')
    const row = await queryOne<{ count: string; envelope: unknown }>(
      "select count(*)::text as count, min(pubkey) as envelope from user_keys where status = 'active'",
    )
    expect(row?.count).toBe('1')
    expect(row?.envelope).toBe(pubkey)
  })

  it('refuses a second registration for an email that already has a passkey', async () => {
    await register('ada@example.test')
    const again = await post('/auth/register/options', { email: 'ada@example.test' })
    expect(again.status).toBe(409)
  })

  it('rejects a challenge it never issued', async () => {
    const device = authenticator()
    const forged = device.register('ZmFrZS1jaGFsbGVuZ2U')
    const response = await post('/auth/register/verify', forged)
    expect(response.status).toBe(400)
  })

  it('rejects a replayed registration challenge', async () => {
    const device = authenticator()
    const options = (await (
      await post('/auth/register/options', { email: 'ada@example.test' })
    ).json()) as { challenge: string }

    const first = await post('/auth/register/verify', device.register(options.challenge))
    expect(first.status).toBe(200)

    const replay = await post('/auth/register/verify', device.register(options.challenge))
    expect(replay.status).toBe(400)
  })
})

describe('login', () => {
  it('signs in with an enrolled passkey', async () => {
    const { device, pubkey } = await register('ada@example.test')

    const options = (await (await post('/auth/login/options', {})).json()) as { challenge: string }
    const response = await post('/auth/login/verify', device.authenticate(options.challenge))

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({ verified: true, pubkey })
  })

  it('refuses an unknown credential', async () => {
    await register('ada@example.test')
    const stranger = authenticator()

    const options = (await (await post('/auth/login/options', {})).json()) as { challenge: string }
    const response = await post('/auth/login/verify', stranger.authenticate(options.challenge))

    expect(response.status).toBe(401)
  })

  it('refuses a replayed authentication challenge', async () => {
    const { device } = await register('ada@example.test')
    const options = (await (await post('/auth/login/options', {})).json()) as { challenge: string }

    expect((await post('/auth/login/verify', device.authenticate(options.challenge))).status).toBe(
      200,
    )
    expect((await post('/auth/login/verify', device.authenticate(options.challenge))).status).toBe(
      400,
    )
  })
})

describe('multiple devices', () => {
  // The PEEK-26 headline: one passkey per person is a support incident waiting
  // to happen, so enrolling a second device must work before anyone needs it.
  it('enrols a second device and lets it sign in independently', async () => {
    const { cookie, pubkey } = await register('ada@example.test')

    const options = (await (await post('/auth/credentials/options', {}, cookie)).json()) as {
      challenge: string
    }

    const laptop = authenticator()
    const enrolled = await post('/auth/register/verify', laptop.register(options.challenge))
    expect(enrolled.status).toBe(200)

    const list = await app.request('/me/credentials', { headers: { cookie } })
    await expect(list.json()).resolves.toMatchObject({
      credentials: [{ backedUp: false }, { backedUp: false }],
    })

    // The new device signs in on its own, with no reference to the first.
    const loginOptions = (await (await post('/auth/login/options', {})).json()) as {
      challenge: string
    }
    const login = await post('/auth/login/verify', laptop.authenticate(loginOptions.challenge))
    expect(login.status).toBe(200)
    await expect(login.json()).resolves.toMatchObject({ verified: true, pubkey })
  })

  it('requires a session to enrol another passkey', async () => {
    await register('ada@example.test')
    const response = await post('/auth/credentials/options', {})
    expect(response.status).toBe(401)
  })

  it('revokes a credential, and the revoked device can no longer sign in', async () => {
    const { cookie } = await register('ada@example.test')

    const options = (await (await post('/auth/credentials/options', {}, cookie)).json()) as {
      challenge: string
    }
    const laptop = authenticator()
    await post('/auth/register/verify', laptop.register(options.challenge))

    const credentials = (await (
      await app.request('/me/credentials', { headers: { cookie } })
    ).json()) as { credentials: { id: string }[] }
    const laptopRow = credentials.credentials[1]
    if (!laptopRow) throw new Error('expected two credentials')

    const revoked = await app.request(`/me/credentials/${laptopRow.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(revoked.status).toBe(200)

    const loginOptions = (await (await post('/auth/login/options', {})).json()) as {
      challenge: string
    }
    const login = await post('/auth/login/verify', laptop.authenticate(loginOptions.challenge))
    expect(login.status).toBe(401)
  })

  // Stage 1 has no recovery flow, so letting someone revoke their last passkey
  // would strand them outside their own identity.
  it('refuses to revoke the only passkey', async () => {
    const { cookie } = await register('ada@example.test')
    const credentials = (await (
      await app.request('/me/credentials', { headers: { cookie } })
    ).json()) as { credentials: { id: string }[] }

    const response = await app.request(`/me/credentials/${credentials.credentials[0]?.id}`, {
      method: 'DELETE',
      headers: { cookie },
    })
    expect(response.status).toBe(409)
  })

  it('will not let one user revoke another user’s passkey', async () => {
    const ada = await register('ada@example.test')
    const grace = await register('grace@example.test')

    // Give Ada a second credential so the last-passkey rule is not what refuses.
    const options = (await (await post('/auth/credentials/options', {}, ada.cookie)).json()) as {
      challenge: string
    }
    await post('/auth/register/verify', authenticator().register(options.challenge))

    const adaCredentials = (await (
      await app.request('/me/credentials', { headers: { cookie: ada.cookie } })
    ).json()) as { credentials: { id: string }[] }

    const response = await app.request(`/me/credentials/${adaCredentials.credentials[0]?.id}`, {
      method: 'DELETE',
      headers: { cookie: grace.cookie },
    })
    expect(response.status).toBe(404)
  })
})

describe('sessions', () => {
  it('rejects requests with no session', async () => {
    expect((await app.request('/me')).status).toBe(401)
  })

  it('invalidates the session on logout', async () => {
    const { cookie } = await register('ada@example.test')
    expect((await post('/auth/logout', {}, cookie)).status).toBe(200)
    expect((await app.request('/me', { headers: { cookie } })).status).toBe(401)
  })
})
