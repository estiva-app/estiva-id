/**
 * NIP-OA, checked against the spec vector Buzz's own implementation pins.
 *
 * The signature below is not one of ours: it is the vector in
 * `crates/buzz-sdk/src/nip_oa.rs`, asserted there by `test_verify_spec_test_vector`
 * against the Rust verifier that will judge everything this module produces.
 * Pinning it here is what makes "our preimage matches theirs" a fact rather than
 * a reading of the source — a one-character difference in the preimage produces
 * a tag that is cryptographically perfect and refused by the relay, which is the
 * least debuggable failure this feature has available.
 *
 * BIP-340 signing draws auxiliary randomness, so our *output* cannot be pinned
 * byte-for-byte. Verifying somebody else's fixed signature over the same
 * preimage tests the same agreement from the other side.
 */
import { schnorr } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils'
import { describe, expect, it } from 'vitest'
import {
  assertValidConditions,
  authPreimage,
  authTagHeaderValue,
  computeAuthTag,
  verifyAuthTag,
} from './nip-oa.js'

/** The generator point's x-coordinate — the spec vector's owner. */
const OWNER_PUBKEY = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
const AGENT_PUBKEY = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5'
const CONDITIONS = 'kind=1&created_at<1713957000'
const SPEC_SIG =
  '8b7df2575caf0a108374f8471722b233c53f9ff827a8b0f91861966c3b9dd5cb2e189eae9f49d72187674c2f5bd244145e10ff86c9f257ffe65a1ee5f108b369'

const secretKey = (hex: string) => Buffer.from(hex, 'hex')
const OWNER_SK = secretKey('ab4fe32a0c6bcda236f862539b2da61558df77181efa4d0b770f97ca8e549f71')
const AGENT_SK = secretKey('548cab35fc5fc4e4a3b2fd52c3ce490c8f125c767f2d20f9e212ba03f5539664')
const ownerPk = bytesToHex(schnorr.getPublicKey(OWNER_SK))
const agentPk = bytesToHex(schnorr.getPublicKey(AGENT_SK))

describe('the spec vector', () => {
  it('builds the preimage the spec names', () => {
    expect(authPreimage(AGENT_PUBKEY, CONDITIONS)).toBe(
      `nostr:agent-auth:${AGENT_PUBKEY}:${CONDITIONS}`,
    )
  })

  it("verifies Buzz's pinned signature", () => {
    expect(verifyAuthTag(['auth', OWNER_PUBKEY, CONDITIONS, SPEC_SIG], AGENT_PUBKEY)).toBe(
      OWNER_PUBKEY,
    )
  })

  /**
   * The reason the vector is worth having. Signing a *different* preimage
   * produces a tag that verifies against itself and is refused by the relay, so
   * only an external signature can catch a preimage that drifted.
   */
  it('rejects the same signature over a preimage that differs by one character', () => {
    const wrongPreimage = `nostr:agent-auth:${AGENT_PUBKEY}:${CONDITIONS} `
    const digest = sha256(utf8ToBytes(wrongPreimage))
    expect(schnorr.verify(SPEC_SIG, digest, OWNER_PUBKEY)).toBe(false)
  })
})

describe('computeAuthTag', () => {
  it('produces a tag naming the owner, which our verifier recovers', () => {
    const tag = computeAuthTag(OWNER_SK, agentPk)
    expect(tag[0]).toBe('auth')
    expect(tag[1]).toBe(ownerPk)
    expect(tag[2]).toBe('')
    expect(tag[3]).toMatch(/^[0-9a-f]{128}$/)
    expect(verifyAuthTag(tag, agentPk)).toBe(ownerPk)
  })

  it('derives the owner pubkey from the secret rather than trusting a caller', () => {
    // There is no parameter to pass a different owner through — the only way to
    // change who a tag names is to hold a different key.
    expect(computeAuthTag(OWNER_SK, agentPk)[1]).toBe(ownerPk)
    expect(computeAuthTag(AGENT_SK, ownerPk)[1]).toBe(agentPk)
  })

  it('binds the attestation to one agent key', () => {
    const tag = computeAuthTag(OWNER_SK, agentPk)
    const other = bytesToHex(schnorr.getPublicKey(secretKey('11'.repeat(32))))
    expect(() => verifyAuthTag(tag, other)).toThrow(/verification failed/)
  })

  it('refuses self-attestation, which the relay also refuses', () => {
    expect(() => computeAuthTag(OWNER_SK, ownerPk)).toThrow(/must differ/)
    expect(() => verifyAuthTag(['auth', ownerPk, '', 'a'.repeat(128)], ownerPk)).toThrow(
      /must differ/,
    )
  })

  it('refuses an agent pubkey that is not 64 lowercase hex', () => {
    expect(() => computeAuthTag(OWNER_SK, agentPk.toUpperCase())).toThrow(/64 lowercase hex/)
    expect(() => computeAuthTag(OWNER_SK, `${agentPk}00`)).toThrow(/64 lowercase hex/)
  })

  it('travels as the raw JSON array', () => {
    const tag = computeAuthTag(OWNER_SK, agentPk)
    expect(JSON.parse(authTagHeaderValue(tag))).toEqual(tag)
  })
})

describe('conditions', () => {
  it.each([
    '',
    'kind=0',
    'kind=65535',
    'created_at<0',
    'created_at>4294967295',
    'kind=9&created_at<1713957000',
  ])('accepts %j', (conditions) => {
    expect(() => assertValidConditions(conditions)).not.toThrow()
  })

  /**
   * Every one of these is refused by the relay *after* it has checked the
   * signature, so without this the failure arrives as an opaque relay rejection
   * three hops from the code that chose the value.
   */
  it.each([
    ['kind=65536', /out of range/],
    ['kind=09', /leading zero/],
    ['kind=1&', /empty clause/],
    ['&kind=1', /empty clause/],
    ['kind=1&&kind=2', /empty clause/],
    ['kind=1 & kind=2', /whitespace/],
    ['kind=', /unsupported clause/],
    ['expires=1', /unsupported clause/],
    ['created_at=1', /unsupported clause/],
    ['created_at>4294967296', /out of range/],
    ['kind=-1', /unsupported clause/],
    ['kind=+1', /unsupported clause/],
  ])('refuses %j', (conditions, message) => {
    expect(() => assertValidConditions(conditions as string)).toThrow(message as RegExp)
    expect(() => computeAuthTag(OWNER_SK, agentPk, conditions as string)).toThrow(message as RegExp)
  })
})

describe('verifyAuthTag structural checks', () => {
  const good = () => computeAuthTag(OWNER_SK, agentPk)

  it('refuses a tag that is not four elements', () => {
    expect(() => verifyAuthTag(['auth', ownerPk, ''], agentPk)).toThrow(/4 elements/)
    expect(() => verifyAuthTag([...good(), 'extra'], agentPk)).toThrow(/4 elements/)
    expect(() => verifyAuthTag('not an array', agentPk)).toThrow(/4 elements/)
  })

  it('refuses a tag not labelled "auth"', () => {
    const [, owner, conditions, sig] = good()
    expect(() => verifyAuthTag(['notauth', owner, conditions, sig], agentPk)).toThrow(/"auth"/)
  })

  it('refuses a tampered signature', () => {
    const tag = good()
    const forged = [...tag]
    forged[3] = `00000000${tag[3].slice(8)}`
    expect(() => verifyAuthTag(forged, agentPk)).toThrow(/verification failed/)
  })

  it('refuses malformed owner and signature hex', () => {
    const [, , conditions, sig] = good()
    expect(() => verifyAuthTag(['auth', 'nothex', conditions, sig], agentPk)).toThrow(
      /owner pubkey/,
    )
    expect(() => verifyAuthTag(['auth', ownerPk, conditions, 'short'], agentPk)).toThrow(
      /signature/,
    )
  })
})
