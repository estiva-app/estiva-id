/**
 * PEEK-65: adding a person, and the fact that nobody else can add themselves.
 *
 * Registration was open until this. The gate is the point, so most of what is
 * checked here is what no longer works — and the bootstrap, because a gate with
 * no way through it locks out the operator too.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query, queryOne } from '../../db/pool.js'
import { createInvite } from '../../domain/invites.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey } from '../../domain/users.js'
import { SoftwareAuthenticator } from '../../test/authenticator.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()
const cfg = config()

const post = (path: string, body: unknown, cookie?: string) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body ?? {}),
  })

async function signedInAs(email: string, role: 'admin' | 'member') {
  const user = await createUserWithKey({ email, role })
  const { token } = await createSession({ userId: user.id })
  return { user, cookie: `estiva_id_session=${token}` }
}

beforeAll(async () => {
  // A handle cannot be assigned without a workspace host to assemble it
  // against — see `saveProfile`. Unset, the claim below is a no-op rather than
  // an error, which is exactly what caught this test out.
  process.env.COMMUNITY_HOST = 'estiva.test'
  const { resetConfigForTests } = await import('../../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
})

afterAll(async () => {
  await closePool()
})

describe('the gate', () => {
  it('refuses enrolment with no invite at all', async () => {
    const response = await post('/auth/register/options', { email: 'nobody@example.test' })
    expect(response.status).toBe(400)
  })

  it('refuses an invite token that was never issued', async () => {
    const response = await post('/auth/register/options', { inviteToken: 'not-a-real-token' })
    expect(response.status).toBe(403)
  })

  it('refuses an expired invite', async () => {
    const invite = await createInvite({ email: 'late@example.test', createdBy: null })
    await query("update invites set expires_at = now() - interval '1 hour'")

    const response = await post('/auth/register/options', { inviteToken: invite.token })
    expect(response.status).toBe(403)
    expect(await response.text()).toContain('expired')
  })

  /**
   * Single use, and burned only once a passkey exists — so the second person
   * handed the same link finds it dead, while the first person's cancelled
   * browser prompt does not cost them the invite (below).
   */
  it('refuses an invite that has already been enrolled against', async () => {
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })
    const device = new SoftwareAuthenticator({
      rpId: cfg.RP_ID,
      origin: cfg.RP_ORIGINS[0] as string,
    })

    const options = (await (
      await post('/auth/register/options', { inviteToken: invite.token })
    ).json()) as { challenge: string }
    expect((await post('/auth/register/verify', device.register(options.challenge))).status).toBe(
      200,
    )

    const again = await post('/auth/register/options', { inviteToken: invite.token })
    expect(again.status).toBe(403)
    expect(await again.text()).toContain('already been used')
  })

  // The most common way enrolment fails is somebody dismissing the passkey
  // prompt. Burning the link there would turn a mis-click into a support
  // request, so the invite survives an abandoned attempt.
  it('survives an abandoned enrolment, and lands on the same account', async () => {
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })

    const first = await post('/auth/register/options', { inviteToken: invite.token })
    expect(first.status).toBe(200)

    const second = await post('/auth/register/options', { inviteToken: invite.token })
    expect(second.status).toBe(200)

    const users = await queryOne<{ count: string }>('select count(*)::text as count from users')
    expect(users?.count).toBe('1')
  })

  // The invite carries the address; the invitee does not choose it. A link that
  // let you pick your own email would be transferable to anyone.
  it('takes the email from the invite, not from the request', async () => {
    const invite = await createInvite({
      email: 'invited@example.test',
      displayName: 'Invited Person',
      createdBy: null,
    })
    const device = new SoftwareAuthenticator({
      rpId: cfg.RP_ID,
      origin: cfg.RP_ORIGINS[0] as string,
    })

    const options = (await (
      await post('/auth/register/options', {
        inviteToken: invite.token,
        email: 'attacker@example.test',
      })
    ).json()) as { challenge: string }
    const verify = await post('/auth/register/verify', device.register(options.challenge))
    const cookie = (verify.headers.get('set-cookie') ?? '').split(';')[0] as string

    const me = await app.request('/me', { headers: { cookie } })
    await expect(me.json()).resolves.toMatchObject({ email: 'invited@example.test' })
  })

  it('claims the handle the admin reserved', async () => {
    const invite = await createInvite({ email: 'ada@example.test', handle: 'ada', createdBy: null })
    const device = new SoftwareAuthenticator({
      rpId: cfg.RP_ID,
      origin: cfg.RP_ORIGINS[0] as string,
    })

    const options = (await (
      await post('/auth/register/options', { inviteToken: invite.token })
    ).json()) as { challenge: string }
    const verify = await post('/auth/register/verify', device.register(options.challenge))
    const cookie = (verify.headers.get('set-cookie') ?? '').split(';')[0] as string

    const profile = await app.request('/me/profile', { headers: { cookie } })
    await expect(profile.json()).resolves.toMatchObject({ handle: 'ada' })
  })
})

describe('POST /invites', () => {
  it('lets an admin invite somebody, and returns the link exactly once', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')

    const response = await post('/invites', { email: 'new@example.test', handle: 'newbie' }, cookie)
    expect(response.status).toBe(201)

    const body = (await response.json()) as { url: string; email: string; role: string }
    expect(body.email).toBe('new@example.test')
    expect(body.role).toBe('member')
    expect(body.url).toContain('/?invite=')

    // Only the hash is stored, so nothing can hand the token back later.
    const stored = await queryOne<{ present: boolean }>(
      'select exists (select 1 from invites where token_hash is not null) as present',
    )
    expect(stored?.present).toBe(true)
  })

  it('refuses a member', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    const response = await post('/invites', { email: 'new@example.test' }, cookie)
    expect(response.status).toBe(403)
  })

  it('refuses a stranger', async () => {
    const response = await post('/invites', { email: 'new@example.test' })
    expect(response.status).toBe(401)
  })

  // Two identities for one human is the failure this whole project exists to
  // prevent, so it is refused at the point of invitation rather than later.
  it('refuses to invite an address that already exists', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await createUserWithKey({ email: 'taken@example.test' })

    const response = await post('/invites', { email: 'taken@example.test' }, cookie)
    expect(response.status).toBe(409)
  })

  it('never writes the token to the audit log', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const response = await post('/invites', { email: 'new@example.test' }, cookie)
    const { url } = (await response.json()) as { url: string }
    const token = url.split('invite=')[1] as string

    const audit = await queryOne<{ blob: string }>(
      "select coalesce(string_agg(detail::text, ' '), '') as blob from audit_events",
    )
    expect(audit?.blob).not.toContain(token)
  })

  it('shows an admin who has been invited but has not finished', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await post('/invites', { email: 'pending@example.test' }, cookie)

    const list = await app.request('/invites', { headers: { cookie } })
    const { invites } = (await list.json()) as { invites: { email: string; started: boolean }[] }
    expect(invites).toHaveLength(1)
    expect(invites[0]).toMatchObject({ email: 'pending@example.test', started: false })
  })
})

describe('GET /invites/:token', () => {
  it('prefills the enrolment screen for somebody with no session', async () => {
    const invite = await createInvite({
      email: 'ada@example.test',
      displayName: 'Ada',
      handle: 'ada',
      createdBy: null,
    })

    const response = await app.request(`/invites/${invite.token}`)
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({
      valid: true,
      email: 'ada@example.test',
      displayName: 'Ada',
      handle: 'ada',
    })
  })

  // One status for every failure, so a caller cannot probe which tokens exist.
  it('answers 404 for unknown, expired and consumed alike', async () => {
    expect((await app.request('/invites/nope')).status).toBe(404)

    const invite = await createInvite({ email: 'late@example.test', createdBy: null })
    await query("update invites set expires_at = now() - interval '1 hour'")
    const expired = await app.request(`/invites/${invite.token}`)
    expect(expired.status).toBe(404)
    await expect(expired.json()).resolves.toMatchObject({ valid: false, reason: 'expired' })
  })
})
