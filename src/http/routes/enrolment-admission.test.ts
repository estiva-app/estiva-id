/**
 * PEEK-65: *"an admin can add a colleague who then signs into both apps, having
 * only ever touched a passkey."*
 *
 * Everything except the last clause has worked for a while. Invites, the
 * enrolment screen, the minted key and the reserved handle all landed — and the
 * person they produced could sign in *here* and read nothing in either app,
 * because the relay runs closed and had never heard of their pubkey. Onboarding
 * is two operations against two systems and this service could only do the
 * first, so `admitMember` was written for PEEK-94 and had no callers.
 *
 * These pin the second operation happening, and — just as importantly — the
 * three things that must not happen with it: enrolment must not fail when the
 * relay is down, a second device must not re-ask, and the handle must not be
 * published before the pubkey is admitted, because a closed relay would drop it.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { config } from '../../config.js'
import { closePool } from '../../db/pool.js'
import { listAudit } from '../../domain/audit-log.js'
import { createInvite } from '../../domain/invites.js'
import { getProfile } from '../../domain/profile.js'
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

/**
 * Every event the service publishes, in order.
 *
 * Kinds are what these tests assert on: 9030 is the membership add, 0 is the
 * profile. Their *order* is the contract — the reverse would have the relay
 * drop a profile from a pubkey it does not yet admit.
 */
function captureRelay(respond: () => Response = () => new Response('{}', { status: 200 })) {
  const kinds: number[] = []
  vi.stubGlobal('fetch', async (_input: unknown, init?: RequestInit) => {
    const body = init?.body ? (JSON.parse(String(init.body)) as { kind?: number }) : {}
    if (typeof body.kind === 'number') kinds.push(body.kind)
    return respond()
  })
  return kinds
}

/** Run an invite all the way to a working passkey, as the real screen does. */
async function enrol(inviteToken: string) {
  const device = new SoftwareAuthenticator({
    rpId: cfg.RP_ID,
    origin: cfg.RP_ORIGINS[0] as string,
  })
  const options = (await (await post('/auth/register/options', { inviteToken })).json()) as {
    challenge: string
  }
  return post('/auth/register/verify', device.register(options.challenge))
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
})

afterAll(async () => {
  await closePool()
})

describe('enrolling admits the pubkey', () => {
  /**
   * The done-when, reduced to its one missing step. Before this, the colleague
   * finished enrolment holding a key the relay would refuse every event from.
   */
  it('publishes a membership add for the new pubkey', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })

    await withOperator(operator.id, async () => {
      const kinds = captureRelay()
      expect((await enrol(invite.token)).status).toBe(200)
      expect(kinds).toContain(9030)
    })
  })

  /**
   * Order is the contract, not an implementation detail. `canonicalize_nip05`
   * runs during profile sync and a closed relay drops events from pubkeys it
   * does not admit — so a `kind:0` sent first is simply lost, leaving a handle
   * that resolves nowhere and nothing saying why.
   */
  it('admits before publishing the handle, never the other way round', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({
      email: 'ada@example.test',
      handle: 'ada',
      createdBy: null,
    })

    await withOperator(operator.id, async () => {
      const kinds = captureRelay()
      await enrol(invite.token)

      expect(kinds).toContain(9030)
      expect(kinds).toContain(0)
      expect(kinds.indexOf(9030)).toBeLessThan(kinds.indexOf(0))
    })
  })

  /** The reserved handle now actually reaches the relay, rather than waiting
   * for a save on the account page that nobody knew to make. */
  it('leaves the invited handle on the profile', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({
      email: 'ada@example.test',
      handle: 'ada',
      createdBy: null,
    })

    const userId = await withOperator(operator.id, async () => {
      captureRelay()
      const response = await enrol(invite.token)
      expect(response.status).toBe(200)
      const [entry] = await listAudit({ action: 'relay.admit' })
      return entry?.subjectUserId as string
    })

    await expect(getProfile(userId)).resolves.toMatchObject({ handle: 'ada' })
  })

  it('records the admission, naming the person it was for', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })

    await withOperator(operator.id, async () => {
      captureRelay()
      await enrol(invite.token)

      const [entry] = await listAudit({ action: 'relay.admit' })
      expect(entry).toMatchObject({ outcome: 'success', actorType: 'system' })
      expect(entry?.detail).toMatchObject({ viaEnrolment: true })
    })
  })
})

describe('what must not break when the relay is unavailable', () => {
  /**
   * The person has a working passkey and a session by this point. Refusing
   * would strand an account they can already authenticate to, over a step an
   * admin can complete from the people list — so it degrades, exactly as
   * offboarding's fourth step does.
   */
  it('still completes enrolment when the relay refuses', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })

    await withOperator(operator.id, async () => {
      captureRelay(() => new Response('down', { status: 503 }))

      const response = await enrol(invite.token)

      expect(response.status).toBe(200)
      expect(await response.json()).toMatchObject({ verified: true })
    })
  })

  /** A failure that left no record would be invisible — the person looks
   * enrolled, and only the relay knows they cannot read anything. */
  it('records the failure rather than swallowing it', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })

    await withOperator(operator.id, async () => {
      captureRelay(() => new Response('down', { status: 503 }))
      await enrol(invite.token)

      const [entry] = await listAudit({ action: 'relay.admit' })
      expect(entry?.outcome).toBe('error')
      expect(entry?.detail).toHaveProperty('reason')
    })
  })

  /**
   * With no operator configured there is nothing to sign a 9030 with. That is
   * the pre-PEEK-94 posture, and enrolment must survive it rather than becoming
   * newly dependent on a config value that used to be optional.
   */
  it('still completes enrolment with no operator identity at all', async () => {
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })
    captureRelay()

    const response = await enrol(invite.token)

    expect(response.status).toBe(200)
    const [entry] = await listAudit({ action: 'relay.admit' })
    expect(entry?.outcome).toBe('error')
    expect(entry?.detail).toMatchObject({ reason: expect.stringContaining('RELAY_OPERATOR') })
  })
})

describe('a second device is not a second admission', () => {
  /**
   * Adding a passkey to an existing account shares this route and has no
   * invite. The pubkey was admitted the first time round, so re-asking would be
   * a round trip to be told `alreadyInState` — and a `relay.admit` record for
   * something that was not an onboarding.
   */
  it('does not re-admit when enrolling another passkey', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const invite = await createInvite({ email: 'ada@example.test', createdBy: null })

    await withOperator(operator.id, async () => {
      const kinds = captureRelay()
      // Enrolment signs the person in, so the cookie it sets is what the second
      // device's ceremony authenticates with — the real path, not a proxy for it.
      const first = await enrol(invite.token)
      const cookie = first.headers.get('set-cookie')?.split(';')[0] as string
      expect(cookie).toContain('estiva_id_session')
      expect(await listAudit({ action: 'relay.admit' })).toHaveLength(1)

      const before = kinds.filter((kind) => kind === 9030).length
      const device = new SoftwareAuthenticator({
        rpId: cfg.RP_ID,
        origin: cfg.RP_ORIGINS[0] as string,
      })
      const options = (await (await post('/auth/credentials/options', {}, cookie)).json()) as {
        challenge: string
      }
      const second = await post('/auth/register/verify', device.register(options.challenge), cookie)

      expect(second.status).toBe(200)
      // No invite to consume, so no onboarding happened — the pubkey was
      // admitted when the account was created and has not changed since.
      expect(kinds.filter((kind) => kind === 9030)).toHaveLength(before)
      expect(await listAudit({ action: 'relay.admit' })).toHaveLength(1)
    })
  })
})
