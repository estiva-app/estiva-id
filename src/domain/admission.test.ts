/**
 * PEEK-94: the admission column stops saying "Not known".
 *
 * The one property worth more than the others: **a failure must degrade to
 * `unknown`, never to `not-admitted`**. Those look similar on a screen and mean
 * opposite things — `not-admitted` is a measurement, and inventing one because
 * the relay was briefly unreachable is how a person who *is* admitted gets
 * chased, or worse, how a half-offboarded one gets waved through by a later
 * reader who trusts the column.
 *
 * The operator guards matter for a related reason: every call here is signed by
 * an operator identity rather than by the subject, because the relay restricts
 * membership to owners and admins and the subject is, in every interesting
 * case, precisely not one.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool } from '../db/pool.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { RelayAdmission, UnobservableAdmission } from './admission.js'
import { NoOperatorIdentity, withOperatorSecretKey } from './operator-key.js'
import { revokeMember } from './relay-membership.js'
import { createUserWithKey, setUserStatus } from './users.js'

const PUBKEY_A = 'a'.repeat(64)
const PUBKEY_B = 'b'.repeat(64)

/** Point the config at an operator identity for the duration of one test. */
async function withOperator<T>(userId: string, run: () => Promise<T>): Promise<T> {
  const { resetConfigForTests } = await import('../config.js')
  process.env.RELAY_OPERATOR_USER_ID = userId
  resetConfigForTests()
  try {
    return await run()
  } finally {
    process.env.RELAY_OPERATOR_USER_ID = ''
    resetConfigForTests()
  }
}

const respondWith = (status: number, body: unknown) =>
  vi.stubGlobal('fetch', async () => new Response(JSON.stringify(body), { status }))

beforeAll(async () => {
  process.env.RELAY_BRIDGE_URL = 'https://relay.test'
  process.env.COMMUNITY_HOST = 'estiva.test'
  const { resetConfigForTests } = await import('../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

afterAll(async () => {
  await closePool()
})

describe('reading admission', () => {
  it('reports an admitted pubkey', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await withOperator(operator.id, async () => {
      respondWith(200, { pubkey: PUBKEY_A, admitted: true, role: 'member' })
      expect(await new RelayAdmission().getAdmissionStatus(PUBKEY_A)).toBe('admitted')
    })
  })

  /**
   * A non-member is a `200` with `admitted: false`, not a 404 — the relay is
   * deliberate about that, because "not a member" is an answer and a 404 would
   * be indistinguishable from "no such route".
   */
  it('reports a pubkey nobody admitted', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await withOperator(operator.id, async () => {
      respondWith(200, { pubkey: PUBKEY_A, admitted: false, role: null })
      expect(await new RelayAdmission().getAdmissionStatus(PUBKEY_A)).toBe('not-admitted')
    })
  })

  it('answers a page of people from one roster read, not one call each', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await withOperator(operator.id, async () => {
      let calls = 0
      vi.stubGlobal('fetch', async () => {
        calls++
        return new Response(
          JSON.stringify({ members: [{ pubkey: PUBKEY_A, role: 'member' }], count: 1 }),
          { status: 200 },
        )
      })

      const statuses = await new RelayAdmission().getAdmissionStatuses([PUBKEY_A, PUBKEY_B])

      expect(statuses.get(PUBKEY_A)).toBe('admitted')
      expect(statuses.get(PUBKEY_B)).toBe('not-admitted')
      // The whole reason the batch form exists. N round trips to paint one
      // screen is what a per-pubkey implementation would cost.
      expect(calls).toBe(1)
    })
  })
})

describe('what a failure must never become', () => {
  /**
   * The assertion this file exists for. A relay that cannot be reached tells us
   * nothing about anybody, and saying `not-admitted` would be inventing a
   * measurement — one that reads on screen exactly like a real one.
   */
  it('degrades an unreachable relay to unknown, not to not-admitted', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await withOperator(operator.id, async () => {
      vi.stubGlobal('fetch', async () => {
        throw new Error('ECONNREFUSED')
      })
      expect(await new RelayAdmission().getAdmissionStatus(PUBKEY_A)).toBe('unknown')
    })
  })

  it('degrades a refused operator to unknown', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await withOperator(operator.id, async () => {
      // The operator key is not owner/admin at the relay — a deployment fault,
      // not a fact about the pubkey being asked about.
      respondWith(403, { error: 'only relay owners and admins can read membership' })
      expect(await new RelayAdmission().getAdmissionStatus(PUBKEY_A)).toBe('unknown')
    })
  })

  it('degrades a whole page to unknown rather than marking everyone out', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await withOperator(operator.id, async () => {
      respondWith(500, { error: 'boom' })
      const statuses = await new RelayAdmission().getAdmissionStatuses([PUBKEY_A, PUBKEY_B])
      expect([...statuses.values()]).toEqual(['unknown', 'unknown'])
    })
  })

  it('still answers unknown when no operator is configured at all', async () => {
    respondWith(200, { pubkey: PUBKEY_A, admitted: true })
    expect(await new RelayAdmission().getAdmissionStatus(PUBKEY_A)).toBe('unknown')
  })
})

describe('the operator identity', () => {
  it('refuses to act when none is configured', async () => {
    await expect(withOperatorSecretKey(async () => 'used')).rejects.toBeInstanceOf(
      NoOperatorIdentity,
    )
  })

  it('refuses to act when it names an identity that does not exist', async () => {
    await withOperator('00000000-0000-0000-0000-000000000000', async () => {
      await expect(withOperatorSecretKey(async () => 'used')).rejects.toThrow(/does not exist/)
    })
  })

  /**
   * An offboarded operator must stop driving the relay's membership table, for
   * the same reason an offboarded person stops signing — otherwise disabling it
   * in the console would leave it quietly acting.
   */
  it('refuses to act once offboarded', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await setUserStatus(operator.id, 'offboarded')

    await withOperator(operator.id, async () => {
      await expect(withOperatorSecretKey(async () => 'used')).rejects.toThrow(/not active/)
    })
  })

  it('signs a membership command as the operator, never as the subject', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })

    await withOperator(operator.id, async () => {
      let signedAs: string | undefined
      let signedKind: number | undefined
      vi.stubGlobal('fetch', async (_url: string, init: RequestInit) => {
        const event = JSON.parse(String(init.body)) as { pubkey: string; kind: number }
        signedAs = event.pubkey
        signedKind = event.kind
        return new Response(JSON.stringify({ accepted: true, event_id: 'x' }), { status: 200 })
      })

      const result = await revokeMember(PUBKEY_A)

      expect(result.ok).toBe(true)
      expect(signedKind).toBe(9031)
      // The subject is in a `p` tag; the *signer* is the operator. A leaver
      // could not sign this, which is the whole point.
      expect(signedAs).toBe(operator.pubkey)
      expect(signedAs).not.toBe(PUBKEY_A)
    })
  })
})

describe('the fallback that shipped for months', () => {
  it('still answers unknown for everybody', async () => {
    const port = new UnobservableAdmission()
    expect(await port.getAdmissionStatus(PUBKEY_A)).toBe('unknown')
    expect([...(await port.getAdmissionStatuses([PUBKEY_A, PUBKEY_B])).values()]).toEqual([
      'unknown',
      'unknown',
    ])
  })
})
