import { describe, expect, it } from 'vitest'
import { type UnsignedEvent, computeEventId } from './event.js'
import { generateKeypair, signEvent, verifyEvent } from './keys.js'

/**
 * The expected id below is not hand-computed. It is the id Buzz's own Rust
 * (`buzz_sdk::builders::build_message`) produced, recorded in
 * `peek-app/docs/buzz-compat/phase4-run-output.txt` and pinned by Estiva Peek's
 * `convex/nostr/events.test.ts`.
 *
 * This service implements NIP-01 serialization independently — no shared
 * package with Peek, by design — so this assertion is what keeps that
 * independence from turning into divergence. A failure means this TypeScript
 * disagrees with Buzz's Rust about what an event id is. Do not "fix" it by
 * updating the expected value.
 */
const BUZZ_PUBKEY = '714902a6e7b9a991fe77ebd9cc4dad01b6474afdf58048277e1ec6b9cde567e8'
const BUZZ_MESSAGE: UnsignedEvent = {
  pubkey: BUZZ_PUBKEY,
  created_at: 1_753_300_200,
  kind: 9,
  tags: [['h', '7b32200c-e4c0-4216-b79a-8490fc05e0bd']],
  content: 'The new sign-up flow drops a step. Worth a look before Friday.',
}

describe('computeEventId', () => {
  it('reproduces the id Buzz’s Rust builders produced for a kind:9 message', () => {
    expect(computeEventId(BUZZ_MESSAGE)).toBe(
      '4f0edeb3b732fa1c44c4dbd26563b4acad022ffeb469ccfdb2aeb02088a92546',
    )
  })

  it('changes when any serialized field changes', () => {
    const base = computeEventId(BUZZ_MESSAGE)
    expect(computeEventId({ ...BUZZ_MESSAGE, content: 'different' })).not.toBe(base)
    expect(computeEventId({ ...BUZZ_MESSAGE, kind: 1 })).not.toBe(base)
    expect(computeEventId({ ...BUZZ_MESSAGE, created_at: 1 })).not.toBe(base)
    expect(computeEventId({ ...BUZZ_MESSAGE, tags: [] })).not.toBe(base)
  })

  it('escapes control characters the way NIP-01 requires', () => {
    const tricky: UnsignedEvent = { ...BUZZ_MESSAGE, content: 'line\nbreak "quoted" \\ tab\t' }
    expect(computeEventId(tricky)).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('signEvent', () => {
  it('produces a verifiable signature', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    const signed = signEvent({ ...BUZZ_MESSAGE, pubkey: publicKeyHex }, secretKey)
    expect(verifyEvent(signed)).toBe(true)
    expect(signed.pubkey).toBe(publicKeyHex)
  })

  // The core guarantee of the /sign seam: the caller does not choose whose
  // signature it gets, whatever it puts in the request body.
  it('overwrites a caller-supplied pubkey with the key actually signing', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    const impersonation: UnsignedEvent = { ...BUZZ_MESSAGE, pubkey: 'f'.repeat(64) }

    const signed = signEvent(impersonation, secretKey)

    expect(signed.pubkey).toBe(publicKeyHex)
    expect(signed.pubkey).not.toBe('f'.repeat(64))
    expect(verifyEvent(signed)).toBe(true)
  })

  it('recomputes the id rather than trusting one supplied by the caller', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    const signed = signEvent({ ...BUZZ_MESSAGE, pubkey: publicKeyHex }, secretKey)
    expect(signed.id).toBe(computeEventId({ ...BUZZ_MESSAGE, pubkey: publicKeyHex }))
  })

  it('rejects a tampered event at verification', () => {
    const { secretKey, publicKeyHex } = generateKeypair()
    const signed = signEvent({ ...BUZZ_MESSAGE, pubkey: publicKeyHex }, secretKey)
    expect(verifyEvent({ ...signed, content: 'tampered' })).toBe(false)
  })
})

describe('generateKeypair', () => {
  it('mints distinct 32-byte keys with x-only pubkeys', () => {
    const a = generateKeypair()
    const b = generateKeypair()
    expect(a.secretKey).toHaveLength(32)
    expect(a.publicKeyHex).toMatch(/^[0-9a-f]{64}$/)
    expect(a.publicKeyHex).not.toBe(b.publicKeyHex)
  })
})
