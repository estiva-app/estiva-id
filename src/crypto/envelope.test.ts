import { randomBytes } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { type Envelope, envelopeKids, openEnvelope, sealEnvelope } from './envelope.js'

const KEK = randomBytes(32)
const OTHER_KEK = randomBytes(32)
const KID = 'deploy-1'
const resolve = (kid: string) => (kid === KID ? KEK : undefined)

const AAD = { userId: 'user-a', pubkey: 'a'.repeat(64) }
const SECRET = randomBytes(32)

describe('envelope', () => {
  it('round-trips a secret', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    expect(openEnvelope({ envelope, aad: AAD, resolveKek: resolve })).toEqual(SECRET)
  })

  it('never stores the plaintext secret anywhere in the envelope', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    const serialised = JSON.stringify(envelope)
    expect(serialised).not.toContain(SECRET.toString('base64'))
    expect(serialised).not.toContain(SECRET.toString('hex'))
    expect(serialised).not.toContain(KEK.toString('base64'))
  })

  it('produces different ciphertext for the same secret each time', () => {
    const a = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    const b = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    expect(a.ct).not.toEqual(b.ct)
    expect(a.iv).not.toEqual(b.iv)
  })

  it('refuses to open with the wrong KEK', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    expect(() => openEnvelope({ envelope, aad: AAD, resolveKek: () => OTHER_KEK })).toThrow()
  })

  it('refuses when no KEK is available for any share', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    expect(() => openEnvelope({ envelope, aad: AAD, resolveKek: () => undefined })).toThrow(
      /No available key-encryption key/,
    )
  })

  // The property that matters for a custodial service: an attacker who can move
  // rows around in a dump must not be able to make the service sign as someone
  // else.
  it('refuses to open under a different owner (AAD binding)', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    const impostor = { userId: 'user-b', pubkey: 'b'.repeat(64) }
    expect(() => openEnvelope({ envelope, aad: impostor, resolveKek: resolve })).toThrow()
  })

  it('detects tampering with the ciphertext', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    const bytes = Buffer.from(envelope.ct, 'base64')
    bytes[0] = (bytes[0] ?? 0) ^ 0xff
    const tampered: Envelope = { ...envelope, ct: bytes.toString('base64') }
    expect(() => openEnvelope({ envelope: tampered, aad: AAD, resolveKek: resolve })).toThrow()
  })

  it('detects tampering with a wrapped DEK share', () => {
    const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
    const share = envelope.dek.shares[0]
    if (!share) throw new Error('expected one share')
    const bytes = Buffer.from(share.ct, 'base64')
    bytes[0] = (bytes[0] ?? 0) ^ 0xff
    const tampered: Envelope = {
      ...envelope,
      dek: { ...envelope.dek, shares: [{ ...share, ct: bytes.toString('base64') }] },
    }
    expect(() => openEnvelope({ envelope: tampered, aad: AAD, resolveKek: resolve })).toThrow()
  })

  describe('Stage 4 readiness', () => {
    it('writes a single direct share under one deployment key in Stage 1', () => {
      const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
      expect(envelope.dek.scheme).toBe('direct')
      expect(envelope.dek.threshold).toBe(1)
      expect(envelopeKids(envelope)).toEqual([KID])
    })

    // The claim the format exists to make: adding a custodian must not require
    // re-encrypting the secret. The ciphertext layer is untouched when a second
    // share is added, so a future escrow rollout rewrites a JSON field rather
    // than every row's key material.
    it('can gain a second custodian without re-encrypting the secret', () => {
      const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
      const original = envelope.dek.shares[0]
      if (!original) throw new Error('expected one share')

      const escrowed: Envelope = {
        ...envelope,
        dek: {
          ...envelope.dek,
          shares: [original, { ...original, kid: 'escrow-1' }],
        },
      }

      expect(escrowed.ct).toBe(envelope.ct)
      expect(escrowed.iv).toBe(envelope.iv)
      expect(openEnvelope({ envelope: escrowed, aad: AAD, resolveKek: resolve })).toEqual(SECRET)
      expect(envelopeKids(escrowed)).toEqual([KID, 'escrow-1'])
    })

    it('refuses shamir envelopes rather than guessing at a combiner', () => {
      const envelope = sealEnvelope({ secret: SECRET, aad: AAD, kek: KEK, kid: KID })
      const future: Envelope = {
        ...envelope,
        dek: { ...envelope.dek, scheme: 'shamir', threshold: 2 },
      }
      expect(() => openEnvelope({ envelope: future, aad: AAD, resolveKek: resolve })).toThrow(
        /Stage 4/,
      )
    })
  })
})
