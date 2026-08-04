/**
 * PEEK-27 acceptance.
 *
 * *"Done when: a registered user has a pubkey, the secret is never returned
 * over any API, and a database dump alone does not yield signing keys."*
 */
import { randomBytes } from 'node:crypto'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { type Envelope, openEnvelope } from '../crypto/envelope.js'
import { closePool, queryOne } from '../db/pool.js'
import { signEvent, verifyEvent } from '../nostr/keys.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { currentKid } from './kek.js'
import { getActivePubkey, keyCustodyReport, withUserSecretKey } from './keys.js'
import { createUserWithKey } from './users.js'

beforeAll(async () => {
  await prepareDatabase()
})
beforeEach(async () => {
  await truncateAll()
})
afterAll(async () => {
  await closePool()
})

describe('custody', () => {
  it('gives a registered user a pubkey', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    expect(user.pubkey).toMatch(/^[0-9a-f]{64}$/)
    await expect(getActivePubkey(user.id)).resolves.toBe(user.pubkey)
  })

  it('can sign for the user without the key leaving custody', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })

    const signed = await withUserSecretKey(user.id, (secretKey, pubkey) =>
      signEvent(
        { pubkey, created_at: 1_753_300_200, kind: 9, tags: [], content: 'hello' },
        secretKey,
      ),
    )

    expect(signed.pubkey).toBe(user.pubkey)
    expect(verifyEvent(signed)).toBe(true)
  })

  it('zeroes the secret once the callback returns', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })

    // Deliberately smuggling the buffer out to observe the wipe. Production code
    // must never do this — which is why the API is a callback and not a getter.
    const smuggled = await withUserSecretKey(user.id, (secretKey) => secretKey)
    expect(smuggled.every((byte) => byte === 0)).toBe(true)
  })

  // "A database dump alone does not yield signing keys." The dump is everything
  // in `user_keys`; the KEK is not in it.
  describe('a database dump alone', () => {
    it('stores no plaintext secret anywhere in the row', async () => {
      const user = await createUserWithKey({ email: 'ada@example.test' })
      const row = await queryOne<{ envelope: Envelope }>(
        'select envelope from user_keys where user_id = $1',
        [user.id],
      )
      const dump = JSON.stringify(row)

      const secretHex = await withUserSecretKey(user.id, (secretKey) => secretKey.toString('hex'))
      expect(dump).not.toContain(secretHex)
      expect(dump).not.toContain(Buffer.from(secretHex, 'hex').toString('base64'))

      // The pubkey *is* in the envelope, as AAD. That is deliberate: it is
      // public, and binding it is what stops a moved row signing as its new
      // owner.
      expect(dump).toContain(user.pubkey)
    })

    it('cannot be decrypted without the deployment key', async () => {
      const user = await createUserWithKey({ email: 'ada@example.test' })
      const row = await queryOne<{ envelope: Envelope }>(
        'select envelope from user_keys where user_id = $1',
        [user.id],
      )
      if (!row) throw new Error('expected a key row')

      // An attacker with the dump but not the environment.
      const attackerKek = randomBytes(32)
      expect(() =>
        openEnvelope({
          envelope: row.envelope,
          aad: { userId: user.id, pubkey: user.pubkey },
          resolveKek: () => attackerKek,
        }),
      ).toThrow()
    })

    it('cannot be made to sign as someone else by moving rows', async () => {
      const ada = await createUserWithKey({ email: 'ada@example.test' })
      const grace = await createUserWithKey({ email: 'grace@example.test' })

      const adaRow = await queryOne<{ envelope: Envelope }>(
        'select envelope from user_keys where user_id = $1',
        [ada.id],
      )
      if (!adaRow) throw new Error('expected a key row')

      // Ada's envelope moved onto Grace's row: AAD binding must reject it
      // rather than quietly signing Grace's events with Ada's key.
      await queryOne('update user_keys set envelope = $1 where user_id = $2', [
        JSON.stringify(adaRow.envelope),
        grace.id,
      ])

      await expect(withUserSecretKey(grace.id, (secretKey) => secretKey.length)).rejects.toThrow()
    })
  })

  it('reports which deployment key holds custody, without exposing it', async () => {
    await createUserWithKey({ email: 'ada@example.test' })
    await createUserWithKey({ email: 'grace@example.test' })

    // Against the configured kid, not a literal — CI runs under a different one,
    // and the claim is "custody is held by the deployment key", not "by test-1".
    const report = await keyCustodyReport()
    expect(report).toEqual([{ kid: currentKid(), count: 2 }])
  })
})
