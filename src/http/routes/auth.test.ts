/**
 * PEEK-26 acceptance, driven through real WebAuthn ceremonies.
 *
 * *"Done when: a person can register, sign in from a second device, and
 * list/revoke their own credentials."*
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query, queryOne } from '../../db/pool.js'
import { createInvite } from '../../domain/invites.js'
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

/**
 * Register a fresh user and return their cookie, authenticator and pubkey.
 *
 * Enrolment needs an invite since PEEK-65, so one is minted directly rather
 * than through `POST /invites` — that route needs an admin, and an admin needs
 * an enrolment, which is the loop `scripts/create-invite.ts` exists to break.
 */
async function register(email: string, role: 'admin' | 'member' = 'member') {
  const device = authenticator()
  const invite = await createInvite({
    email,
    displayName: 'Test User',
    role,
    createdBy: null,
  })

  const optionsResponse = await post('/auth/register/options', { inviteToken: invite.token })
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

  // Even a fresh, valid invite cannot mint a second identity for an address
  // that can already sign in — that would be one human with two pubkeys, the
  // exact thing this project exists to prevent.
  it('refuses a second registration for an email that already has a passkey', async () => {
    await register('ada@example.test')
    const second = await createInvite({ email: 'ada@example.test', createdBy: null })

    const again = await post('/auth/register/options', { inviteToken: second.token })
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
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })
    const options = (await (
      await post('/auth/register/options', { inviteToken: invite.token })
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

  /**
   * The 2026-08-17 incident, in three tests.
   *
   * A colleague's second passkey failed twice with a 500 and no audit record.
   * The options asked for `userVerification: 'preferred'`, their authenticator
   * duly skipped UV, and `verifyRegistrationResponse` — which requires UV unless
   * told otherwise — threw rather than returning `verified: false`, so the
   * refusal branch never ran. Their device kept the credential this service had
   * refused to store, and offered it at every subsequent sign-in.
   *
   * The suite missed it because the software authenticator always set UV.
   */
  it('asks the authenticator to verify the user, rather than merely preferring it', async () => {
    const { cookie } = await register('ada@example.test')

    const enrol = await (await post('/auth/credentials/options', {}, cookie)).json()
    expect(enrol).toMatchObject({
      authenticatorSelection: { userVerification: 'required' },
    })

    const login = await (await post('/auth/login/options', {})).json()
    expect(login).toMatchObject({ userVerification: 'required' })
  })

  it('refuses an unverified second passkey without a 500, and says so in the audit log', async () => {
    const { cookie } = await register('ada@example.test')

    const options = (await (await post('/auth/credentials/options', {}, cookie)).json()) as {
      challenge: string
    }

    const laptop = authenticator()
    const enrolled = await post(
      '/auth/register/verify',
      laptop.register(options.challenge, { userVerified: false }),
    )
    expect(enrolled.status).toBe(403)

    // Nothing was stored, so the credential the device kept is not a passkey here.
    const list = await app.request('/me/credentials', { headers: { cookie } })
    await expect(list.json()).resolves.toMatchObject({ credentials: [{ backedUp: false }] })

    const audited = await query<{ outcome: string; detail: Record<string, unknown> }>(
      "select outcome, detail from audit_events where action = 'passkey.register' and outcome = 'refused'",
    )
    expect(audited.rows).toHaveLength(1)
    expect(audited.rows[0]?.detail).toMatchObject({ reason: 'verification_failed' })
    expect(String(audited.rows[0]?.detail.refusal)).toContain('user could not be verified')
  })

  it('refuses an unverified sign-in without a 500', async () => {
    const { device } = await register('ada@example.test')

    const options = (await (await post('/auth/login/options', {})).json()) as { challenge: string }
    const login = await post(
      '/auth/login/verify',
      device.authenticate(options.challenge, undefined, { userVerified: false }),
    )
    expect(login.status).toBe(401)
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

  /**
   * The half of "I lost my laptop" that revoking a passkey does not cover:
   * the credential can no longer authenticate, but sessions it already minted
   * stay valid until they expire.
   */
  it('revokes other sessions and keeps the one that asked', async () => {
    const { device, cookie: first } = await register('ada@example.test')

    // A second sign-in on the same account — the lost laptop.
    const optionsResponse = await post('/auth/login/options', {})
    const options = (await optionsResponse.json()) as { challenge: string }
    const loginResponse = await post('/auth/login/verify', device.authenticate(options.challenge))
    expect(loginResponse.status).toBe(200)
    const second = sessionCookie(loginResponse)

    const revoked = await post('/me/sessions/revoke-others', {}, second)
    expect(revoked.status).toBe(200)
    expect(await revoked.json()).toEqual({ revoked: 1 })

    // The caller stays signed in; the other session is gone.
    expect((await app.request('/me', { headers: { cookie: second } })).status).toBe(200)
    expect((await app.request('/me', { headers: { cookie: first } })).status).toBe(401)
  })

  it('needs a session of its own', async () => {
    expect((await post('/me/sessions/revoke-others', {})).status).toBe(401)
  })
})
