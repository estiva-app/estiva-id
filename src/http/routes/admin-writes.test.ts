/**
 * The admin console's write side — PEEK-102's two repairs, and PEEK-65's one.
 *
 * PEEK-64 built a console that was almost entirely read-only, with offboarding
 * as the single exception. That was right about which action most needed to be
 * atomic and wrong about which ones needed to exist: a console that can only
 * take things away leaves every mis-click to be undone over SSH, which is how a
 * QA cleanup that offboarded the relay operator ended in a hand-written
 * `update users set status='active'` against production.
 *
 * So there are three writes here now, and what these pin is the shape of each
 * refusal as much as each success — a button that is offered and then declined
 * teaches an admin that the screen is decorative.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool } from '../../db/pool.js'
import {
  type AdmissionStatus,
  UnobservableAdmission,
  setAdmissionPort,
} from '../../domain/admission.js'
import type { DirectoryEntry } from '../../domain/directory.js'
import { offboardPerson } from '../../domain/offboarding.js'
import { createRoleIdentity } from '../../domain/roles.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey, findUserById, setUserStatus } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

async function signedInAs(email: string, role: 'admin' | 'member') {
  const user = await createUserWithKey({ email, role })
  const { token } = await createSession({ userId: user.id })
  return { user, cookie: `estiva_id_session=${token}` }
}

const post = (path: string, cookie: string) =>
  app.request(path, { method: 'POST', headers: { cookie } })

function relayAccepts() {
  vi.stubGlobal(
    'fetch',
    async () => new Response(JSON.stringify({ accepted: true, event_id: 'abc' }), { status: 200 }),
  )
}

/** Answer every pubkey with one status, so a row's admission is decidable. */
function admissionIs(status: AdmissionStatus) {
  setAdmissionPort({
    getAdmissionStatus: async () => status,
    getAdmissionStatuses: async (pubkeys) => new Map(pubkeys.map((key) => [key, status])),
    lastUnknownReason: () => (status === 'unknown' ? 'unreachable' : null),
  })
}

async function withOperator<T>(operatorId: string, run: () => Promise<T>): Promise<T> {
  const { resetConfigForTests } = await import('../../config.js')
  process.env.RELAY_OPERATOR_USER_ID = operatorId
  resetConfigForTests()
  try {
    return await run()
  } finally {
    process.env.RELAY_OPERATOR_USER_ID = ''
    resetConfigForTests()
  }
}

beforeAll(async () => {
  process.env.COMMUNITY_HOST = 'estiva.test'
  process.env.RELAY_BRIDGE_URL = 'https://relay.test'
  const { resetConfigForTests } = await import('../../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  vi.unstubAllGlobals()
  setAdmissionPort(new UnobservableAdmission())
})

afterAll(async () => {
  await closePool()
})

describe('offboarding the operator is refused at the door (PEEK-102)', () => {
  it('answers 400 with a reason the console can branch on', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })

    await withOperator(operator.id, async () => {
      relayAccepts()
      const response = await post(`/admin/people/${operator.id}/offboard`, cookie)

      expect(response.status).toBe(400)
      const body = (await response.json()) as { error: { detail?: { reason?: string } } }
      expect(body.error.detail?.reason).toBe('operator_identity')
    })
  })
})

describe('reinstating from the console (PEEK-102)', () => {
  it('brings somebody back without a database edit', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    relayAccepts()
    await offboardPerson(leaver.id)

    const response = await post(`/admin/people/${leaver.id}/reinstate`, cookie)

    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ userId: leaver.id, needsRecovery: true })
  })

  /**
   * The operator case end to end: offboarded by an earlier mistake, reinstated
   * from the console, and admitted again — which is the leg a status flip alone
   * would have skipped, leaving every roster read still refused.
   */
  it('re-admits the pubkey, not only the status', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    relayAccepts()
    await offboardPerson(operator.id)

    // Configured only now — mirroring the real order, where the operator was
    // offboarded while it was still the configured one.
    const body = await withOperator(operator.id, async () => {
      const response = await post(`/admin/people/${operator.id}/reinstate`, cookie)
      expect(response.status).toBe(200)
      return (await response.json()) as { relayAdmission: { admitted: boolean } }
    })

    expect(body.relayAdmission.admitted).toBe(true)
  })

  it('refuses somebody who was never offboarded', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const active = await createUserWithKey({ email: 'active@example.test' })

    const response = await post(`/admin/people/${active.id}/reinstate`, cookie)

    expect(response.status).toBe(409)
    const body = (await response.json()) as { error: { detail?: { reason?: string } } }
    expect(body.error.detail?.reason).toBe('not_offboarded')
  })

  it('is not a way for a member to restore an account', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    relayAccepts()
    await offboardPerson(leaver.id)

    expect((await post(`/admin/people/${leaver.id}/reinstate`, cookie)).status).toBe(403)
  })
})

describe('admitting by hand (PEEK-65)', () => {
  it('admits somebody enrolment left out', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const ada = await createUserWithKey({ email: 'ada@example.test' })
    admissionIs('not-admitted')

    const body = await withOperator(operator.id, async () => {
      relayAccepts()
      const response = await post(`/admin/people/${ada.id}/admit`, cookie)
      expect(response.status).toBe(200)
      return (await response.json()) as { admitted: boolean }
    })

    expect(body.admitted).toBe(true)
  })

  /**
   * Admitting somebody this service has already disabled would re-open the half
   * that offboarding closed, and leave the two systems disagreeing in the
   * dangerous direction. Reinstating is the action that does both.
   */
  it('refuses to admit an offboarded identity', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const leaver = await createUserWithKey({ email: 'leaver@example.test' })
    relayAccepts()
    await offboardPerson(leaver.id)
    admissionIs('not-admitted')

    const response = await post(`/admin/people/${leaver.id}/admit`, cookie)

    expect(response.status).toBe(400)
    const body = (await response.json()) as { error: { detail?: { reason?: string } } }
    expect(body.error.detail?.reason).toBe('not_active')
  })

  it('is not a way for a member to grant relay access', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    const ada = await createUserWithKey({ email: 'ada@example.test' })

    expect((await post(`/admin/people/${ada.id}/admit`, cookie)).status).toBe(403)
  })
})

describe('why admission is unknown (PEEK-102)', () => {
  /**
   * The heart of the ticket's third finding: four causes, one grey chip. The
   * console after somebody offboarded the operator looked exactly like the
   * console before PEEK-94 shipped, and like a workspace with no operator at
   * all — so nothing about the screen could tell an admin which had happened.
   */
  it('names the cause beside the list, not on every row', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await createUserWithKey({ email: 'ada@example.test' })
    admissionIs('unknown')

    const response = await app.request('/admin/people', { headers: { cookie } })
    const body = (await response.json()) as {
      people: DirectoryEntry[]
      admissionUnknownReason: string | null
    }

    expect(body.admissionUnknownReason).toBe('unreachable')
    // One workspace-wide fact, carried once — not repeated per person, which
    // would imply it had been measured for each of them.
    expect(body.people.every((person) => !('admissionUnknownReason' in person))).toBe(true)
  })

  it('says nothing when admission was read successfully', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await createUserWithKey({ email: 'ada@example.test' })
    admissionIs('admitted')

    const response = await app.request('/admin/people', { headers: { cookie } })
    const body = (await response.json()) as { admissionUnknownReason: string | null }

    expect(body.admissionUnknownReason).toBeNull()
  })

  /**
   * The distinction that was being thrown away. `withOperatorSecretKey` raises
   * `NoOperatorIdentity` for an offboarded operator, and the catch reported it
   * as `unreachable` — blaming Buzz for a decision made in this service, and
   * sending whoever read it to check whether the relay was up.
   */
  it('blames the operator identity, not the relay, when it is not active', async () => {
    const { RelayAdmission } = await import('../../domain/admission.js')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    relayAccepts()
    await offboardPerson(operator.id)

    await withOperator(operator.id, async () => {
      const port = new RelayAdmission()
      await expect(port.getAdmissionStatus('abc')).resolves.toBe('unknown')
      expect(port.lastUnknownReason()).toBe('operator-inactive')
    })
  })

  /**
   * Caught by running the real server rather than by any test: with the
   * operator configured but `RELAY_BRIDGE_URL` unset, a single `not-configured`
   * label had the console tell an admin to set `RELAY_OPERATOR_USER_ID` — which
   * was already set. One label, two faults, wrong fix; the same mistake this
   * field exists to end, one level down.
   */
  it('tells a missing relay apart from a missing operator', async () => {
    const { RelayAdmission } = await import('../../domain/admission.js')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const { resetConfigForTests } = await import('../../config.js')

    process.env.RELAY_BRIDGE_URL = ''
    try {
      await withOperator(operator.id, async () => {
        const port = new RelayAdmission()
        await expect(port.getAdmissionStatus('abc')).resolves.toBe('unknown')
        expect(port.lastUnknownReason()).toBe('relay-not-configured')
      })
    } finally {
      process.env.RELAY_BRIDGE_URL = 'https://relay.test'
      resetConfigForTests()
    }
  })

  /** A reason must not outlive the outage that caused it. */
  it('clears the reason once a read succeeds again', async () => {
    const { RelayAdmission } = await import('../../domain/admission.js')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })

    await withOperator(operator.id, async () => {
      const port = new RelayAdmission()

      vi.stubGlobal('fetch', async () => new Response('down', { status: 503 }))
      await port.getAdmissionStatus('abc')
      expect(port.lastUnknownReason()).toBe('unreachable')

      vi.stubGlobal(
        'fetch',
        async () => new Response(JSON.stringify({ admitted: true }), { status: 200 }),
      )
      await expect(port.getAdmissionStatus('abc')).resolves.toBe('admitted')
      expect(port.lastUnknownReason()).toBeNull()
    })
  })
})

describe('the operator is marked on the list (PEEK-102)', () => {
  it('flags the identity everything else is measured with', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const ada = await createUserWithKey({ email: 'ada@example.test' })

    const people = await withOperator(operator.id, async () => {
      const response = await app.request('/admin/people', { headers: { cookie } })
      return ((await response.json()) as { people: DirectoryEntry[] }).people
    })

    expect(people.find((person) => person.id === operator.id)?.isOperator).toBe(true)
    expect(people.find((person) => person.id === ada.id)?.isOperator).toBe(false)
  })
})

/**
 * Granting admin (PEEK-163).
 *
 * Admin was settable only at account creation, so a workspace whose only admin
 * left had no route back that did not involve `psql` — and, more immediately, no
 * first admin could share the console with a second person, because every route
 * on it is `adminOnly`.
 *
 * What these pin is mostly the refusals. A grant is easy to get right and fails
 * loudly; the refusals are the half that quietly matter, because each one is a
 * state the caller could not have known from the row they clicked.
 */
describe('granting and withdrawing admin', () => {
  const setRole = (id: string, role: 'admin' | 'member', cookie: string) =>
    app.request(`/admin/people/${id}/role`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ role }),
    })

  it('promotes a member, and the change is what they are afterwards', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { user } = await signedInAs('kat@example.test', 'member')

    const response = await setRole(user.id, 'admin', cookie)
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({
      from: 'member',
      to: 'admin',
      changed: true,
    })

    // Read back rather than trusting the reply: the reply is the thing under test.
    expect((await findUserById(user.id))?.role).toBe('admin')
  })

  it('and the promoted person can then use the console', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const kat = await signedInAs('kat@example.test', 'member')

    expect((await app.request('/admin/people', { headers: { cookie: kat.cookie } })).status).toBe(
      403,
    )
    await setRole(kat.user.id, 'admin', cookie)
    expect((await app.request('/admin/people', { headers: { cookie: kat.cookie } })).status).toBe(
      200,
    )
  })

  it('withdraws it again, so a mis-click is not permanent', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { user } = await signedInAs('kat@example.test', 'admin')

    await expect((await setRole(user.id, 'member', cookie)).json()).resolves.toMatchObject({
      from: 'admin',
      to: 'member',
    })
    expect((await findUserById(user.id))?.role).toBe('member')
  })

  it('writes nothing when the role is already what was asked for', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { user } = await signedInAs('kat@example.test', 'member')

    await expect((await setRole(user.id, 'member', cookie)).json()).resolves.toMatchObject({
      changed: false,
    })
  })

  it('needs an admin', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    const { user } = await signedInAs('kat@example.test', 'member')
    expect((await setRole(user.id, 'admin', cookie)).status).toBe(403)
  })

  /**
   * The one nobody recovers from without shell access.
   *
   * It doubles as the guarantee that a workspace always keeps an admin: since
   * an admin may only change somebody *else*, they are always left standing.
   */
  it('refuses to let an admin change their own role', async () => {
    const { user, cookie } = await signedInAs('admin@example.test', 'admin')

    const response = await setRole(user.id, 'member', cookie)
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'self_role_change' } },
    })
    expect((await findUserById(user.id))?.role).toBe('admin')
  })

  /**
   * `createRoleIdentity` defaults a bot to `member` on purpose, to keep "is
   * this a person" and "what may they do" independent. Promoting one here would
   * quietly re-correlate them and hand a workspace-admin role to something no
   * passkey guards.
   */
  it('refuses to make a bot an admin', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })

    const response = await setRole(bot.id, 'admin', cookie)
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'not_a_human' } },
    })
  })

  /*
    A dormant privilege is worse than a refused one: reinstating checks status,
    not what the account was granted while it was away.
  */
  it('refuses an offboarded identity', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { user } = await signedInAs('kat@example.test', 'member')
    await setUserStatus(user.id, 'offboarded')

    const response = await setRole(user.id, 'admin', cookie)
    expect(response.status).toBe(400)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'not_active' } },
    })
  })

  it('404s for somebody who does not exist', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    expect((await setRole('00000000-0000-0000-0000-000000000000', 'admin', cookie)).status).toBe(
      404,
    )
  })

  it('refuses a role that is not a role', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { user } = await signedInAs('kat@example.test', 'member')
    const response = await app.request(`/admin/people/${user.id}/role`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ role: 'owner' }),
    })
    expect(response.status).toBe(400)
  })
})
