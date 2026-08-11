/**
 * PEEK-102: *"offboarding the operator identity is either refused or
 * unmistakably warned about, and an offboarded identity can be reinstated
 * without touching the database."*
 *
 * Both halves come from one incident. A QA cleanup during PEEK-94 offboarded the
 * disposable identities and took the `Relay Operator` with them — so offboarding,
 * now that it worked, revoked its own admission and disabled the feature it had
 * just shipped. Recovering needed `update users set status='active'` against
 * production, because removal had a surface and its reverse did not.
 *
 * What these pin is that neither of those is reachable again: the refusal, and a
 * reinstatement that actually restores *both* halves — status here and admission
 * there. A reinstatement that flipped the status alone would have looked like it
 * worked and left every roster read still 403ing, which is the specific way the
 * original incident stayed broken.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool } from '../db/pool.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { listAudit } from './audit-log.js'
import { insertCredential, listActiveCredentials } from './credentials.js'
import { OperatorIdentity, offboardPerson } from './offboarding.js'
import { NoSuchPerson, NotOffboarded, reinstatePerson } from './reinstate.js'
import { createUserWithKey, findUserById } from './users.js'

/** Accept whatever is published, so the relay legs can be exercised. */
function relayAccepts() {
  vi.stubGlobal(
    'fetch',
    async () => new Response(JSON.stringify({ accepted: true, event_id: 'abc' }), { status: 200 }),
  )
}

async function person(email: string) {
  const user = await createUserWithKey({ email, displayName: email.split('@')[0] })
  await insertCredential({
    userId: user.id,
    credentialId: `cred-${email}`,
    publicKey: new Uint8Array([1, 2, 3]),
    signCount: 0,
    transports: ['internal'],
    backedUp: false,
  })
  return user
}

/** Point the config at a role identity and run something with it operating. */
async function withOperator<T>(operatorId: string, run: () => Promise<T>): Promise<T> {
  const { resetConfigForTests } = await import('../config.js')
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

describe('the operator identity cannot be offboarded', () => {
  /**
   * The exact sequence that happened on production. Without the guard this call
   * succeeds, and in succeeding it removes the workspace's ability to read or
   * change anyone's admission — including its own way back.
   */
  it('refuses, rather than disabling admission for the whole workspace', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })

    await withOperator(operator.id, async () => {
      relayAccepts()
      await expect(offboardPerson(operator.id)).rejects.toBeInstanceOf(OperatorIdentity)
    })

    // Not merely refused at the door — nothing was withdrawn on the way to the
    // refusal, so the identity is still fully able to operate.
    await expect(findUserById(operator.id)).resolves.toMatchObject({ status: 'active' })
  })

  /** The way out is a config change, so the refusal has to name the config. */
  it('names what would have to change first', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })

    await withOperator(operator.id, async () => {
      relayAccepts()
      await expect(offboardPerson(operator.id)).rejects.toThrow(/RELAY_OPERATOR_USER_ID/)
    })
  })

  /**
   * The guard is about which identity this is, not about role identities in
   * general — offboarding an ordinary bot stays perfectly legal.
   */
  it('does not protect every other service identity', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const bot = await createUserWithKey({ displayName: 'Release Bot', kind: 'role' })

    await withOperator(operator.id, async () => {
      relayAccepts()
      await expect(offboardPerson(bot.id)).resolves.toMatchObject({ userId: bot.id })
    })
  })

  /**
   * Guarded in the domain rather than in the route, so a script gets the same
   * answer as the button. With no operator configured there is nothing to
   * protect and the check must not fire on an arbitrary identity.
   */
  it('protects nobody when no operator is configured', async () => {
    const someone = await createUserWithKey({ displayName: 'Somebody', kind: 'role' })
    relayAccepts()
    await expect(offboardPerson(someone.id)).resolves.toMatchObject({ userId: someone.id })
  })
})

describe('reinstating without a database edit', () => {
  it('puts the account back, and re-admits the pubkey', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const leaver = await person('leaver@example.test')

    await withOperator(operator.id, async () => {
      relayAccepts()
      await offboardPerson(leaver.id)
      await expect(findUserById(leaver.id)).resolves.toMatchObject({ status: 'offboarded' })

      const result = await reinstatePerson(leaver.id)

      expect(result.relayAdmission.admitted).toBe(true)
      await expect(findUserById(leaver.id)).resolves.toMatchObject({ status: 'active' })
    })
  })

  /**
   * The half that made the incident unrecoverable rather than merely annoying.
   * A status flip alone leaves the pubkey absent from `relay_members`, so every
   * roster read still 403s — a reinstatement that looks like it worked.
   */
  it('reports the relay leg separately when it fails', async () => {
    const operator = await createUserWithKey({ displayName: 'Relay Operator', kind: 'role' })
    const leaver = await person('leaver@example.test')

    await withOperator(operator.id, async () => {
      relayAccepts()
      await offboardPerson(leaver.id)

      vi.stubGlobal('fetch', async () => new Response('down', { status: 503 }))
      const result = await reinstatePerson(leaver.id)

      // Local first, and it must not be held hostage to the relay being up.
      await expect(findUserById(leaver.id)).resolves.toMatchObject({ status: 'active' })
      expect(result.relayAdmission.admitted).toBe(false)
      expect(result.relayAdmission.command).toContain('buzz-admin add-member')
      expect(result.relayAdmission.command).toContain(leaver.pubkey)
    })
  })

  /**
   * Passkeys stay revoked. Offboarding took them because the devices holding
   * them were leaving with the person, and handing them back would restore
   * access to whatever prompted the offboarding.
   */
  it('does not give passkeys back, and says a recovery link is needed', async () => {
    const leaver = await person('leaver@example.test')
    relayAccepts()
    await offboardPerson(leaver.id)

    const result = await reinstatePerson(leaver.id)

    expect(result.needsRecovery).toBe(true)
    await expect(listActiveCredentials(leaver.id)).resolves.toHaveLength(0)
  })

  /**
   * A role identity never had a passkey — it signs with a client credential,
   * which offboarding never touched. So it comes back whole, which is what makes
   * this a complete fix for the operator case rather than a partial one.
   */
  it('brings a role identity back whole, with nothing left to do', async () => {
    const bot = await createUserWithKey({ displayName: 'Release Bot', kind: 'role' })
    relayAccepts()
    await offboardPerson(bot.id)

    const result = await reinstatePerson(bot.id)

    expect(result.needsRecovery).toBe(false)
    await expect(findUserById(bot.id)).resolves.toMatchObject({ status: 'active' })
  })

  it('refuses somebody who is not offboarded', async () => {
    const active = await person('active@example.test')
    await expect(reinstatePerson(active.id)).rejects.toBeInstanceOf(NotOffboarded)
  })

  it('refuses an id that is nobody', async () => {
    await expect(reinstatePerson('00000000-0000-0000-0000-000000000000')).rejects.toBeInstanceOf(
      NoSuchPerson,
    )
  })

  /**
   * Reinstating is exactly as consequential as offboarding and gets the same
   * treatment: an admin restoring access and an admin seizing an account are the
   * same call with a different status, and only the record tells them apart.
   */
  it('records who did it, to whom, and what was left outstanding', async () => {
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    const leaver = await person('leaver@example.test')
    relayAccepts()
    await offboardPerson(leaver.id)

    await reinstatePerson(leaver.id, { actorUserId: admin.id })

    const [entry] = await listAudit({ action: 'user.reinstate' })
    expect(entry).toMatchObject({
      actorUserId: admin.id,
      subjectUserId: leaver.id,
      outcome: 'success',
    })
    expect(entry?.detail).toMatchObject({ needsRecovery: true, relayAdmissionRestored: false })
  })
})
