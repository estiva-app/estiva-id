/**
 * PEEK-64: the people list.
 *
 * Most of what matters here is what the list refuses to hide. A person who
 * never finished enrolling, and a person whose standing at the relay nobody can
 * check, both have to appear as themselves rather than as an ordinary member —
 * those are the two states that are otherwise invisible until somebody
 * complains.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query } from '../../db/pool.js'
import { type AdmissionStatus, setAdmissionPort } from '../../domain/admission.js'
import { UnobservableAdmission } from '../../domain/admission.js'
import type { DirectoryEntry } from '../../domain/directory.js'
import { createInvite } from '../../domain/invites.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { SoftwareAuthenticator } from '../../test/authenticator.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()
const cfg = config()

async function signedInAs(email: string, role: 'admin' | 'member') {
  const user = await createUserWithKey({ email, role })
  const { token } = await createSession({ userId: user.id })
  return { user, cookie: `estiva_id_session=${token}` }
}

const people = async (cookie: string) => {
  const response = await app.request('/admin/people', { headers: { cookie } })
  const body = (await response.json()) as { people: DirectoryEntry[] }
  return { status: response.status, people: body.people }
}

const byEmail = (list: DirectoryEntry[], email: string) =>
  list.find((entry) => entry.email === email)

beforeAll(async () => {
  process.env.COMMUNITY_HOST = 'estiva.test'
  const { resetConfigForTests } = await import('../../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  setAdmissionPort(new UnobservableAdmission())
})

afterAll(async () => {
  await closePool()
})

describe('who may read the directory', () => {
  it('lets an admin see everyone', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await createUserWithKey({ email: 'member@example.test' })

    const { status, people: list } = await people(cookie)
    expect(status).toBe(200)
    expect(list.map((entry) => entry.email).sort()).toEqual([
      'admin@example.test',
      'member@example.test',
    ])
  })

  it('refuses a member', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    expect((await people(cookie)).status).toBe(403)
  })

  it('answers a stranger with 401, not 403', async () => {
    // 403 would confirm the route exists to somebody with no session at all.
    const response = await app.request('/admin/people')
    expect(response.status).toBe(401)
  })

  /**
   * Status is checked before role. An admin who has been offboarded but whose
   * session has not expired must not still be able to read the directory —
   * otherwise offboarding an admin is a change that takes effect in ten minutes.
   */
  it('refuses an admin who is no longer active', async () => {
    const { user, cookie } = await signedInAs('admin@example.test', 'admin')
    await setUserStatus(user.id, 'suspended')

    // setUserStatus revokes sessions, so re-issue one to isolate the role check
    // from the session check and prove it is not the only thing standing here.
    const { token } = await createSession({ userId: user.id })
    expect((await people(`estiva_id_session=${token}`)).status).toBe(403)
  })
})

describe('the states that are otherwise invisible', () => {
  /**
   * The half-onboarded person: invite opened, user row and custodied key made,
   * passkey prompt dismissed. They own a pubkey and cannot sign in, and nothing
   * anywhere else says so.
   */
  it('shows somebody who started enrolling and never finished', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const invite = await createInvite({ email: 'halfway@example.test', createdBy: null })

    await app.request('/auth/register/options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ inviteToken: invite.token }),
    })

    const entry = byEmail((await people(cookie)).people, 'halfway@example.test')
    expect(entry).toMatchObject({ kind: 'user', enrolment: 'enrolling', passkeyCount: 0 })
    // They have a key even though they cannot use it — which is exactly why
    // this state needs naming rather than reading as "not set up yet".
    expect(entry?.pubkey).toMatch(/^[0-9a-f]{64}$/)
  })

  it('shows an invite nobody has opened, and stops showing it once they do', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const invite = await createInvite({ email: 'pending@example.test', createdBy: null })

    const before = byEmail((await people(cookie)).people, 'pending@example.test')
    expect(before).toMatchObject({ kind: 'invite', enrolment: 'invited', status: null })
    expect(before?.expiresAt).not.toBeNull()

    await app.request('/auth/register/options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ inviteToken: invite.token }),
    })

    // Once claimed there is a user row, and listing both would show one person
    // twice — as an outstanding invite and as the account they actually have.
    const after = (await people(cookie)).people.filter(
      (entry) => entry.email === 'pending@example.test',
    )
    expect(after).toHaveLength(1)
    expect(after[0]).toMatchObject({ kind: 'user', enrolment: 'enrolling' })
  })

  it('reports admission as unknown rather than guessing', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const entry = byEmail((await people(cookie)).people, 'admin@example.test')
    expect(entry?.admission).toBe('unknown')
  })

  /**
   * The dangerous mismatch: gone from here, still admitted at the relay. It is
   * only visible because the two live side by side on one row.
   */
  it('shows an offboarded person who is still admitted at the relay', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    await setUserStatus(leaver.id, 'offboarded')

    setAdmissionPort({
      getAdmissionStatus: async (): Promise<AdmissionStatus> => 'admitted',
      getAdmissionStatuses: async (pubkeys) =>
        new Map(pubkeys.map((key) => [key, 'admitted' as AdmissionStatus])),
      lastUnknownReason: () => null,
    })

    const entry = byEmail((await people(cookie)).people, 'leaver@example.test')
    expect(entry).toMatchObject({ status: 'offboarded', admission: 'admitted' })
  })
})

describe('a person in full', () => {
  it('shows their passkeys without handing over the material', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const invite = await createInvite({ email: 'ada@example.test', handle: 'ada', createdBy: null })
    const device = new SoftwareAuthenticator({
      rpId: cfg.RP_ID,
      origin: cfg.RP_ORIGINS[0] as string,
    })

    const options = (await (
      await app.request('/auth/register/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ inviteToken: invite.token }),
      })
    ).json()) as { challenge: string }
    await app.request('/auth/register/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(device.register(options.challenge)),
    })

    const ada = byEmail((await people(cookie)).people, 'ada@example.test')
    const response = await app.request(`/admin/people/${ada?.id}`, { headers: { cookie } })
    expect(response.status).toBe(200)

    const body = (await response.json()) as {
      person: DirectoryEntry
      credentials: { id: string }[]
    }
    expect(body.person).toMatchObject({
      email: 'ada@example.test',
      handle: 'ada',
      nip05: 'ada@estiva.test',
      enrolment: 'enrolled',
      passkeyCount: 1,
    })
    expect(body.credentials).toHaveLength(1)

    // Summaries only. An admin needs to know a device exists, not what is in it.
    const serialised = JSON.stringify(body.credentials)
    expect(serialised).not.toContain('publicKey')
    expect(serialised).not.toContain('credentialId')
  })

  it('answers 404 for an id that is not a person', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const response = await app.request('/admin/people/00000000-0000-0000-0000-000000000000', {
      headers: { cookie },
    })
    expect(response.status).toBe(404)
  })

  /**
   * An unopened invite is on the list but is not addressable: there is no
   * account to open, and the id is an invite's rather than a user's.
   */
  it('does not resolve an invite id as a person', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await createInvite({ email: 'pending@example.test', createdBy: null })
    const pending = byEmail((await people(cookie)).people, 'pending@example.test')

    const response = await app.request(`/admin/people/${pending?.id}`, { headers: { cookie } })
    expect(response.status).toBe(404)
  })
})

describe('what the list reports about a workspace', () => {
  it('assembles nip05 from the current community host, and leaves it null without a handle', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await query(
      `insert into user_handles (user_id, community_host, handle)
       select id, 'estiva.test', 'chief' from users where email = 'admin@example.test'`,
    )

    const list = (await people(cookie)).people
    expect(byEmail(list, 'admin@example.test')?.nip05).toBe('chief@estiva.test')

    await createUserWithKey({ email: 'nohandle@example.test' })
    expect(byEmail((await people(cookie)).people, 'nohandle@example.test')?.nip05).toBeNull()
  })
})

/**
 * PEEK-69: the log gets a reader.
 *
 * Written since the service was built, read by nobody — which left "custody is
 * acceptable because misuse cannot happen unseen" resting on a table with no
 * viewer.
 */
describe('the audit trail', () => {
  it('lets an admin read it, newest first', async () => {
    const { cookie, user } = await signedInAs('admin@example.test', 'admin')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    await setUserStatus(leaver.id, 'offboarded', { actorUserId: user.id })

    const response = await app.request('/admin/audit', { headers: { cookie } })
    expect(response.status).toBe(200)

    const body = (await response.json()) as {
      entries: { action: string; actorEmail: string | null; subjectEmail: string | null }[]
      nextBefore: string | null
      actions: string[]
    }
    const change = body.entries.find((e) => e.action === 'user.status_change')
    expect(change).toMatchObject({
      actorEmail: 'admin@example.test',
      subjectEmail: 'leaver@example.test',
    })
    expect(body.actions).toContain('user.status_change')
  })

  it('scopes to one person when asked', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const one = await createUserWithKey({ email: 'one@example.test' })
    const two = await createUserWithKey({ email: 'two@example.test' })
    await setUserStatus(one.id, 'suspended')
    await setUserStatus(two.id, 'suspended')

    const response = await app.request(`/admin/audit?person=${one.id}`, { headers: { cookie } })
    const { entries } = (await response.json()) as { entries: { subjectEmail: string | null }[] }
    expect(entries).toHaveLength(1)
    expect(entries[0]?.subjectEmail).toBe('one@example.test')
  })

  it('refuses a member and a stranger', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    expect((await app.request('/admin/audit', { headers: { cookie } })).status).toBe(403)
    expect((await app.request('/admin/audit')).status).toBe(401)
  })

  /**
   * An audit log an admin can edit answers a different question from the one it
   * exists to answer, so there is no write surface at all.
   */
  it('offers no way to change or delete a record', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const response = await app.request('/admin/audit', { method, headers: { cookie } })
      expect(response.status).toBe(404)
    }
  })
})

/** PEEK-66: the one write on this surface. */
describe('offboarding in one action', () => {
  it('lets an admin offboard somebody, and reports what is still outstanding', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })

    const response = await app.request(`/admin/people/${leaver.id}/offboard`, {
      method: 'POST',
      headers: { cookie },
    })
    expect(response.status).toBe(200)

    const body = (await response.json()) as {
      relayAdmission: { revoked: boolean; command: string }
    }
    // The clause the ticket is explicit about: say so rather than report success.
    expect(body.relayAdmission.revoked).toBe(false)
    expect(body.relayAdmission.command).toContain(leaver.pubkey)
  })

  /**
   * There is no recovery flow (PEEK-67), so an admin removing their own last
   * way back in is a mistake nobody undoes without shell access.
   */
  it('refuses to let an admin offboard themselves', async () => {
    const { cookie, user } = await signedInAs('admin@example.test', 'admin')
    const response = await app.request(`/admin/people/${user.id}/offboard`, {
      method: 'POST',
      headers: { cookie },
    })
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'self_offboard' } },
    })
  })

  it('refuses a member and a stranger', async () => {
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    const { cookie } = await signedInAs('member@example.test', 'member')

    expect(
      (
        await app.request(`/admin/people/${leaver.id}/offboard`, {
          method: 'POST',
          headers: { cookie },
        })
      ).status,
    ).toBe(403)
    expect(
      (await app.request(`/admin/people/${leaver.id}/offboard`, { method: 'POST' })).status,
    ).toBe(401)
  })

  it('answers 409 the second time', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    const once = () =>
      app.request(`/admin/people/${leaver.id}/offboard`, { method: 'POST', headers: { cookie } })

    expect((await once()).status).toBe(200)
    expect((await once()).status).toBe(409)
  })
})

/**
 * A regression from PEEK-66 landing on PEEK-64's derivation: offboarding
 * revokes every passkey, so deriving "enrolled" from the *live* count labelled
 * every leaver "never signed in". False, and falsest on the screen an admin
 * checks straight after removing somebody.
 */
describe('enrolment after offboarding', () => {
  it('still says a leaver enrolled, because they did', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const invite = await createInvite({ email: 'leaver@example.test', createdBy: null })
    const device = new SoftwareAuthenticator({
      rpId: cfg.RP_ID,
      origin: cfg.RP_ORIGINS[0] as string,
    })
    const options = (await (
      await app.request('/auth/register/options', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ inviteToken: invite.token }),
      })
    ).json()) as { challenge: string }
    await app.request('/auth/register/verify', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(device.register(options.challenge)),
    })

    const before = byEmail((await people(cookie)).people, 'leaver@example.test')
    expect(before).toMatchObject({ enrolment: 'enrolled', passkeyCount: 1 })

    await app.request(`/admin/people/${before?.id}/offboard`, {
      method: 'POST',
      headers: { cookie },
    })

    const after = byEmail((await people(cookie)).people, 'leaver@example.test')
    // No live passkeys, but they are not "never signed in".
    expect(after).toMatchObject({
      status: 'offboarded',
      enrolment: 'enrolled',
      passkeyCount: 0,
    })
  })
})
