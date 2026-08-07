/**
 * The guards on PEEK-37's key migration.
 *
 * These ran for real against Estiva Peek's two custodied keys and both
 * round-tripped — but the *refusal* paths never fired, and refusing is the
 * behaviour that matters. A migration only gets one chance to be wrong.
 */
import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { generateKeypair, publicKeyFromSecret, signEvent, verifyEvent } from '../nostr/keys.js'
import { checkPair, decryptPeekSecret, encryptPeekSecret } from './peek.js'

const PASSPHRASE = 'a-high-entropy-value-at-least-32-chars-long'

describe('reading Peek’s stored secrets', () => {
  it('round-trips a secret through Peek’s format', () => {
    const { secretKey } = generateKeypair()
    const stored = encryptPeekSecret(secretKey, PASSPHRASE)
    expect(decryptPeekSecret(stored, PASSPHRASE)).toEqual(secretKey)
  })

  it('refuses a wrong passphrase rather than returning rubbish', () => {
    const { secretKey } = generateKeypair()
    const stored = encryptPeekSecret(secretKey, PASSPHRASE)
    expect(() => decryptPeekSecret(stored, 'not-the-passphrase')).toThrow()
  })

  it('refuses a truncated or corrupted blob', () => {
    const { secretKey } = generateKeypair()
    const stored = encryptPeekSecret(secretKey, PASSPHRASE)

    expect(() => decryptPeekSecret(stored.slice(0, 8), PASSPHRASE)).toThrow()

    const bytes = Buffer.from(stored, 'base64')
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0xff
    expect(() => decryptPeekSecret(bytes.toString('base64'), PASSPHRASE)).toThrow()
  })
})

describe('the pubkey guard', () => {
  it('accepts a secret that derives the claimed pubkey', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    expect(checkPair(secretKey, publicKeyHex)).toEqual({ ok: true, pubkey: publicKeyHex })
  })

  // The failure this whole migration is designed around: a key written under
  // someone else's pubkey still works, so nothing looks broken — while every
  // event that person published beforehand quietly stops being theirs.
  it('refuses a secret paired with someone else’s pubkey', () => {
    const mine = generateKeypair()
    const theirs = generateKeypair()

    const result = checkPair(mine.secretKey, theirs.publicKeyHex)

    expect(result.ok).toBe(false)
    if (result.ok) throw new Error('expected refusal')
    expect(result.derived).toBe(mine.publicKeyHex)
    expect(result.claimed).toBe(theirs.publicKeyHex)
  })

  it('refuses a secret paired with a pubkey that is merely close', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    const offByOne = `${publicKeyHex.slice(0, 63)}${publicKeyHex[63] === 'a' ? 'b' : 'a'}`
    expect(checkPair(secretKey, offByOne).ok).toBe(false)
  })

  it('accepts an uppercase claim, since hex case is not identity', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    expect(checkPair(secretKey, publicKeyHex.toUpperCase()).ok).toBe(true)
  })

  it('refuses random bytes that are not the key at all', () => {
    const { publicKeyHex } = generateKeypair()
    expect(checkPair(randomBytes(32), publicKeyHex).ok).toBe(false)
  })
})

describe('end to end: a migrated key still signs as its original identity', () => {
  it('produces signatures verifiable under the pubkey Peek published with', () => {
    // Stand in for a Peek user: a key, stored Peek's way, with its pubkey.
    const original = generateKeypair()
    const stored = encryptPeekSecret(original.secretKey, PASSPHRASE)
    const claimedPubkey = original.publicKeyHex

    // What the migration does: decrypt, verify the pairing, then use it.
    const recovered = decryptPeekSecret(stored, PASSPHRASE)
    expect(checkPair(recovered, claimedPubkey).ok).toBe(true)

    const signed = signEvent(
      {
        pubkey: claimedPubkey,
        created_at: 1_785_000_000,
        kind: 9,
        tags: [],
        content: 'after migration',
      },
      recovered,
    )

    expect(verifyEvent(signed)).toBe(true)
    expect(signed.pubkey).toBe(claimedPubkey)
    expect(publicKeyFromSecret(recovered)).toBe(claimedPubkey)
  })
})
