/**
 * Changing the account asks for the passkey again once the last tap is more
 * than 15 minutes old (AUT-2; Miky, 2026-10-16). A sign-in lasts up to 14
 * days, so a laptop left signed in must not be enough to add a passkey of
 * your own to someone's account, remove theirs, sign their other devices out,
 * or — at an admin's laptop — hand out access or a secret.
 *
 * Confirming moves the tap time of the session you are in and nothing else:
 * no new session, and the 14-day end stays where the sign-in put it.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query, queryOne } from '../../db/pool.js'
import { UnobservableAdmission, setAdmissionPort } from '../../domain/admission.js'
import { createInvite } from '../../domain/invites.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey } from '../../domain/users.js'
import { SoftwareAuthenticator } from '../../test/authenticator.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()
const cfg = config()

function authenticator() {
  return new SoftwareAuthenticator({ rpId: cfg.RP_ID, origin: cfg.RP_ORIGINS[0] as string })
}

async function call(method: string, path: string, cookie?: string, body?: unknown) {
  return app.request(path, {
    method,
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    ...(method === 'GET' ? {} : { body: JSON.stringify(body ?? {}) }),
  })
}

async function reasonOf(response: Response): Promise<string | undefined> {
  const body = (await response.json().catch(() => null)) as {
    error?: { detail?: { reason?: string } }
  } | null
  return body?.error?.detail?.reason
}

/** A person who signed up with a passkey; returns the device and its session cookie. */
async function register(email: string, role: 'admin' | 'member' = 'member') {
  const device = authenticator()
  const invite = await createInvite({ email, displayName: 'Test User', role, createdBy: null })
  const options = (await (
    await call('POST', '/auth/register/options', undefined, { inviteToken: invite.token })
  ).json()) as { challenge: string }
  const verify = await call(
    'POST',
    '/auth/register/verify',
    undefined,
    device.register(options.challenge),
  )
  expect(verify.status).toBe(200)
  const cookie = (verify.headers.get('set-cookie') ?? '').split(';')[0] as string
  return { device, cookie }
}

/** Enrol a second passkey from a session whose tap is fresh. */
async function enrol(cookie: string) {
  const device = authenticator()
  const options = (await (await call('POST', '/auth/credentials/options', cookie)).json()) as {
    challenge: string
  }
  expect(
    (await call('POST', '/auth/register/verify', undefined, device.register(options.challenge)))
      .status,
  ).toBe(200)
  return device
}

/** Make every session's last tap this many seconds ago. */
async function tappedAgo(seconds: number) {
  await query('update sessions set authenticated_at = now() - make_interval(secs => $1)', [seconds])
}

async function confirm(cookie: string, device: SoftwareAuthenticator) {
  const options = (await (await call('POST', '/auth/reauth/options', cookie)).json()) as {
    challenge: string
  }
  return call('POST', '/auth/reauth/verify', cookie, device.authenticate(options.challenge))
}

const STALE = 16 * 60
const credentialCount = async () =>
  Number(
    (
      await queryOne<{ n: string }>(
        'select count(*) as n from webauthn_credentials where revoked_at is null',
      )
    )?.n,
  )
const liveSessionCount = async () =>
  Number(
    (await queryOne<{ n: string }>('select count(*) as n from sessions where revoked_at is null'))
      ?.n,
  )

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  setAdmissionPort(new UnobservableAdmission())
})

afterAll(async () => {
  await closePool()
})

describe('a member more than 15 minutes after the tap', () => {
  it('cannot start adding a passkey until they confirm', async () => {
    const { cookie } = await register('ada@example.test')
    await tappedAgo(STALE)

    const refused = await call('POST', '/auth/credentials/options', cookie)
    expect(refused.status).toBe(403)
    expect(await reasonOf(refused)).toBe('reauth_required')
  })

  it('cannot remove a passkey, and it stays', async () => {
    const { cookie } = await register('ada@example.test')
    await enrol(cookie)
    const [second] = (
      await query<{ id: string }>(
        'select id from webauthn_credentials order by created_at desc limit 1',
      )
    ).rows
    await tappedAgo(STALE)

    const refused = await call('DELETE', `/me/credentials/${second?.id}`, cookie)
    expect(refused.status).toBe(403)
    expect(await reasonOf(refused)).toBe('reauth_required')
    expect(await credentialCount()).toBe(2)
  })

  it('cannot sign the other devices out, and they stay signed in', async () => {
    const { cookie } = await register('ada@example.test')
    const [user] = (await query<{ id: string }>('select id from users')).rows
    await createSession({ userId: user?.id as string })
    await tappedAgo(STALE)

    const refused = await call('POST', '/me/sessions/revoke-others', cookie)
    expect(refused.status).toBe(403)
    expect(await reasonOf(refused)).toBe('reauth_required')
    expect(await liveSessionCount()).toBe(2)
  })

  it('still reads their own account without a tap', async () => {
    const { cookie } = await register('ada@example.test')
    await tappedAgo(STALE)
    expect((await call('GET', '/me/credentials', cookie)).status).toBe(200)
  })
})

describe('within 15 minutes of the tap', () => {
  it('signs the other devices out straight away', async () => {
    const { cookie } = await register('ada@example.test')
    const [user] = (await query<{ id: string }>('select id from users')).rows
    await createSession({ userId: user?.id as string })
    await tappedAgo(14 * 60)

    expect((await call('POST', '/me/sessions/revoke-others', cookie)).status).toBe(200)
    expect(await liveSessionCount()).toBe(1)
  })
})

describe('confirming with the passkey', () => {
  it('lets the change through, in the same session, without moving its 14-day end', async () => {
    const { cookie, device } = await register('ada@example.test')
    await tappedAgo(STALE)
    const before = await queryOne<{ id: string; expires_at: Date }>(
      'select id, expires_at from sessions',
    )

    const confirmed = await confirm(cookie, device)
    expect(confirmed.status).toBe(200)
    expect(confirmed.headers.get('set-cookie')).toBeNull()

    const after = await queryOne<{ id: string; expires_at: Date; tapped_secs: number }>(
      'select id, expires_at, extract(epoch from now() - authenticated_at)::float as tapped_secs from sessions',
    )
    expect(after?.id).toBe(before?.id)
    expect(after?.expires_at.getTime()).toBe(before?.expires_at.getTime())
    expect(after?.tapped_secs).toBeLessThan(5)
    expect(await liveSessionCount()).toBe(1)

    expect((await call('POST', '/auth/credentials/options', cookie)).status).toBe(200)
  })

  it('refuses someone else’s passkey, and the session stays unconfirmed', async () => {
    const ada = await register('ada@example.test')
    const grace = await register('grace@example.test')
    await tappedAgo(STALE)

    const refused = await confirm(ada.cookie, grace.device)
    expect(refused.status).toBe(401)
    expect((await call('POST', '/me/sessions/revoke-others', ada.cookie)).status).toBe(403)
  })

  it('does not count a sign-in challenge as a confirmation', async () => {
    const { cookie, device } = await register('ada@example.test')
    await tappedAgo(STALE)
    const login = (await (await call('POST', '/auth/login/options')).json()) as {
      challenge: string
    }

    const refused = await call(
      'POST',
      '/auth/reauth/verify',
      cookie,
      device.authenticate(login.challenge),
    )
    expect(refused.status).toBe(400)
    expect((await call('POST', '/me/sessions/revoke-others', cookie)).status).toBe(403)
  })

  it('needs a session to confirm', async () => {
    expect((await call('POST', '/auth/reauth/options')).status).toBe(401)
  })
})

describe('an admin more than 15 minutes after the tap', () => {
  async function staleAdmin() {
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    const member = await createUserWithKey({ email: 'member@example.test' })
    const { token } = await createSession({ userId: admin.id })
    await tappedAgo(STALE)
    return { cookie: `estiva_id_session=${token}`, member }
  }

  it('must confirm before handing out access or a secret', async () => {
    const { cookie, member } = await staleAdmin()
    const guarded: Array<[string, string, unknown]> = [
      ['POST', '/invites', { email: 'new@example.test' }],
      ['POST', `/admin/people/${member.id}/recovery`, {}],
      ['POST', `/admin/people/${member.id}/role`, { role: 'admin' }],
      ['POST', '/admin/role-identities', { displayName: 'Agent' }],
      [
        'POST',
        `/admin/role-identities/${member.id}/credential`,
        { clientId: 'x', name: 'x', allowedKinds: [1] },
      ],
      ['PATCH', '/admin/credentials/estiva-peek/kinds', { allowedKinds: [1] }],
    ]
    for (const [method, path, body] of guarded) {
      const response = await call(method, path, cookie, body)
      expect({ path, status: response.status, reason: await reasonOf(response) }).toEqual({
        path,
        status: 403,
        reason: 'reauth_required',
      })
    }
    const role = await queryOne<{ role: string }>('select role from users where id = $1', [
      member.id,
    ])
    expect(role?.role).toBe('member')
    expect(Number((await queryOne<{ n: string }>('select count(*) as n from invites'))?.n)).toBe(0)
  })

  it('offboards without a tap, as decided', async () => {
    const { cookie, member } = await staleAdmin()
    const response = await call('POST', `/admin/people/${member.id}/offboard`, cookie)
    expect(await reasonOf(response)).not.toBe('reauth_required')
    expect(response.status).toBe(200)
  })
})
