/**
 * PEEK-66: *"offboarding is one action, and the person can no longer read or
 * write anything on the relay."*
 *
 * The second clause used to be undeliverable: Buzz appeared to expose no way to
 * drive admission, so the honest outcome was three steps of four plus a named
 * outstanding one.
 *
 * **PEEK-94 closed it** — the relay accepts a signed kind:9031 through the same
 * bridge this service already publishes to. So the fourth step now happens, and
 * what these tests pin is the pair of contracts that replaced "never claims":
 * it is done when it is done, and when it is *not* done the result says so and
 * hands back the command, rather than reporting a success that is not true.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool, queryOne } from '../db/pool.js'
import { createApp } from '../http/app.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { listAudit } from './audit-log.js'
import { listActiveCredentials } from './credentials.js'
import { insertCredential } from './credentials.js'
import { issueToken } from './jwt.js'
import { AlreadyOffboarded, NoSuchPerson, offboardPerson } from './offboarding.js'
import { getProfile, saveProfile } from './profile.js'
import { createSession, resolveSession } from './sessions.js'
import { createUserWithKey, findUserById } from './users.js'

const app = createApp()

/** Accept the profile publish so the attestation step can be exercised. */
function relayAccepts() {
  vi.stubGlobal(
    'fetch',
    async () => new Response(JSON.stringify({ accepted: true, event_id: 'abc' }), { status: 200 }),
  )
}

async function person(email: string, handle?: string) {
  const user = await createUserWithKey({ email, displayName: email.split('@')[0] })
  await insertCredential({
    userId: user.id,
    credentialId: `cred-${email}`,
    publicKey: new Uint8Array([1, 2, 3]),
    signCount: 0,
    transports: ['internal'],
    backedUp: false,
  })
  if (handle) {
    relayAccepts()
    await saveProfile(user.id, { handle })
    vi.unstubAllGlobals()
  }
  return user
}

beforeAll(async () => {
  process.env.COMMUNITY_HOST = 'estiva.test'
  process.env.RELAY_BRIDGE_URL = 'https://relay.test'
  const { resetConfigForTests } = await import('../config.js')
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

describe('one action, and what it withdraws', () => {
  it('revokes every passkey, kills every session, and disables the account', async () => {
    const leaver = await person('leaver@example.test')
    await createSession({ userId: leaver.id })
    const { token } = await createSession({ userId: leaver.id })
    relayAccepts()

    const result = await offboardPerson(leaver.id)

    expect(result.passkeysRevoked).toBe(1)
    expect(result.sessionsRevoked).toBe(2)
    await expect(listActiveCredentials(leaver.id)).resolves.toHaveLength(0)
    await expect(resolveSession(token)).resolves.toBeUndefined()
    await expect(findUserById(leaver.id)).resolves.toMatchObject({ status: 'offboarded' })
  })

  it('withdraws the handle and republishes a profile without it', async () => {
    const leaver = await person('leaver@example.test', 'leaver')
    await expect(getProfile(leaver.id)).resolves.toMatchObject({ handle: 'leaver' })

    let published = ''
    vi.stubGlobal('fetch', async (_input: unknown, init?: RequestInit) => {
      published = String(init?.body ?? '')
      return new Response(JSON.stringify({ accepted: true, event_id: 'abc' }), { status: 200 })
    })

    const result = await offboardPerson(leaver.id)

    expect(result.handleRevoked).toBe('leaver')
    expect(result.attestationPublished).toBe(true)
    await expect(getProfile(leaver.id)).resolves.toMatchObject({ handle: null })
    // Omitting the field is what revokes it — measured against the live relay
    // in PEEK-33, and pinned here so the withdrawal cannot silently stop.
    expect(JSON.parse(JSON.parse(published).content)).not.toHaveProperty('nip05')
  })

  /**
   * The leaver keeps their keypair — that is inherent — and their key row stays
   * active on purpose. Revoking it would make everything they ever signed
   * unattributable, which is the opposite of what offboarding should mean.
   */
  it('leaves the key alone, so their history stays attributable', async () => {
    const leaver = await person('leaver@example.test')
    relayAccepts()
    await offboardPerson(leaver.id)

    const key = await queryOne<{ status: string }>(
      'select status from user_keys where user_id = $1',
      [leaver.id],
    )
    expect(key?.status).toBe('active')
  })
})

describe('the step this service cannot take', () => {
  /**
   * The heart of the ticket: *"if not, it can only do three of the four and
   * must say so loudly rather than reporting success."*
   */
  /**
   * With no operator identity configured there is nothing to sign a kind:9031
   * with, so the fourth step cannot happen — and the result must say so rather
   * than quietly reporting three of four as success. This is the pre-PEEK-94
   * behaviour, reached deliberately instead of by failing.
   */
  it('says the admission step did not happen when it could not', async () => {
    const leaver = await person('leaver@example.test')
    relayAccepts()

    const result = await offboardPerson(leaver.id)

    expect(result.relayAdmission.revoked).toBe(false)
    expect(result.relayAdmission.reason).toContain('RELAY_OPERATOR_USER_ID')
  })

  /**
   * The step that PEEK-94 made possible. Signed as the operator, not the
   * leaver: the relay requires an admin or owner, and a leaver is neither —
   * which is precisely why signing as the subject would fail in the only case
   * that matters.
   */
  it('revokes admission when an operator identity exists', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    process.env.RELAY_OPERATOR_USER_ID = operator.id
    const { resetConfigForTests } = await import('../config.js')
    resetConfigForTests()

    try {
      const leaver = await person('leaver@example.test')
      relayAccepts()

      const result = await offboardPerson(leaver.id)

      expect(result.relayAdmission.revoked).toBe(true)
      expect(result.relayAdmission.command).toBeUndefined()

      const audit = await listAudit({ userId: leaver.id, action: 'user.offboard' })
      expect(audit[0]?.detail).toMatchObject({ relayAdmissionRevoked: true })
    } finally {
      process.env.RELAY_OPERATOR_USER_ID = ''
      resetConfigForTests()
    }
  })

  // Only when the step did not happen — a command handed back beside a success
  // invites somebody to run it again, which for an add would be a no-op and for
  // a remove is merely confusing.
  it('hands back the exact command, with the pubkey already in it', async () => {
    const leaver = await person('leaver@example.test')
    relayAccepts()

    const result = await offboardPerson(leaver.id)
    expect(result.relayAdmission.command).toContain('buzz-admin remove-member')
    expect(result.relayAdmission.command).toContain(leaver.pubkey)
  })

  /**
   * A relay that will not take the withdrawal leaves the handle resolving for
   * anyone reading the old event. The local revocations must still have
   * happened — the one step that can fail must not gate the three that cannot.
   */
  it('still disables the account when the relay refuses the withdrawal', async () => {
    const leaver = await person('leaver@example.test', 'leaver')
    vi.stubGlobal('fetch', async () => new Response('down', { status: 503 }))

    const result = await offboardPerson(leaver.id)

    expect(result.attestationPublished).toBe(false)
    expect(result.publishError).toBeTruthy()
    await expect(findUserById(leaver.id)).resolves.toMatchObject({ status: 'offboarded' })
    await expect(listActiveCredentials(leaver.id)).resolves.toHaveLength(0)
  })
})

describe('what the leaver can no longer do here', () => {
  it('cannot take a token or sign, immediately', async () => {
    const leaver = await person('leaver@example.test')
    const { token: sessionToken } = await createSession({ userId: leaver.id })
    // A JWT minted *before* the offboarding, to prove the check is not merely
    // "we stopped issuing new ones".
    const { token: bearer } = await issueToken({
      pubkey: leaver.pubkey,
      clientId: 'estiva-peek',
    })
    relayAccepts()

    await offboardPerson(leaver.id)
    vi.unstubAllGlobals()

    const tokenAttempt = await app.request('/token', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        cookie: `estiva_id_session=${sessionToken}`,
      },
      body: JSON.stringify({ clientId: 'estiva-peek' }),
    })
    expect(tokenAttempt.status).toBe(401)

    const signAttempt = await app.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer}` },
      body: JSON.stringify({ event: { kind: 9, tags: [], content: 'still here?' } }),
    })
    expect(signAttempt.status).toBe(403)
  })
})

describe('refusals', () => {
  it('refuses to offboard somebody twice', async () => {
    const leaver = await person('leaver@example.test')
    relayAccepts()
    await offboardPerson(leaver.id)
    await expect(offboardPerson(leaver.id)).rejects.toBeInstanceOf(AlreadyOffboarded)
  })

  it('refuses an id that is nobody', async () => {
    await expect(offboardPerson('00000000-0000-0000-0000-000000000000')).rejects.toBeInstanceOf(
      NoSuchPerson,
    )
  })
})

describe('the record it leaves', () => {
  it('names the admin, the person, and what was outstanding', async () => {
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    const leaver = await person('leaver@example.test', 'leaver')
    relayAccepts()

    await offboardPerson(leaver.id, { actorUserId: admin.id })

    const [entry] = await listAudit({ action: 'user.offboard' })
    expect(entry).toMatchObject({
      actorUserId: admin.id,
      subjectUserId: leaver.id,
      outcome: 'success',
    })
    expect(entry?.detail).toMatchObject({
      handleRevoked: 'leaver',
      passkeysRevoked: 1,
      // The gap, recorded rather than implied.
      relayAdmissionRevoked: false,
    })
  })
})
