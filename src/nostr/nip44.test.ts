/**
 * NIP-44 v2, against the reference vectors.
 *
 * `nip44.vectors.json` is the suite from github.com/paulmillr/nip44, which the
 * NIP itself points at — the same file every other implementation is checked
 * against. It is vendored rather than paraphrased because the point is to be
 * judged by somebody else's expectations, not our own.
 *
 * The invalid half matters as much as the valid half. An implementation that
 * encrypts correctly and accepts a forged MAC, a wrong version byte or lenient
 * base64 passes every round-trip test anyone would think to write.
 */
import { readFileSync } from 'node:fs'
import { schnorr } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils'
import { describe, expect, it } from 'vitest'
import {
  MAX_PLAINTEXT_BYTES,
  Nip44Error,
  calcPaddedLen,
  conversationKey,
  decrypt,
  encrypt,
  messageKeys,
} from './nip44.js'

interface Vectors {
  v2: {
    valid: {
      get_conversation_key: { sec1: string; pub2: string; conversation_key: string }[]
      get_message_keys: {
        conversation_key: string
        keys: { nonce: string; chacha_key: string; chacha_nonce: string; hmac_key: string }[]
      }
      calc_padded_len: [number, number][]
      encrypt_decrypt: {
        sec1: string
        sec2: string
        conversation_key: string
        nonce: string
        plaintext: string
        payload: string
      }[]
      encrypt_decrypt_long_msg: {
        conversation_key: string
        nonce: string
        pattern: string
        repeat: number
        plaintext_sha256: string
        payload_sha256: string
      }[]
    }
    invalid: {
      encrypt_msg_lengths: number[]
      get_conversation_key: { sec1: string; pub2: string; note: string }[]
      decrypt: { conversation_key: string; nonce: string; payload: string; note: string }[]
    }
  }
}

const vectors = JSON.parse(
  readFileSync(new URL('./nip44.vectors.json', import.meta.url), 'utf8'),
) as Vectors
const v2 = vectors.v2

/** The vectors give a peer as a full 32-byte x-only pubkey, which is our shape. */
const key = (hex: string) => hexToBytes(hex)

/** The vectors identify the peer by secret key; we need its x-only public half. */
const pubkeyOf = (secretHex: string) => schnorr.getPublicKey(hexToBytes(secretHex))

describe('conversation key', () => {
  it('matches every valid vector', () => {
    for (const vector of v2.valid.get_conversation_key) {
      expect(bytesToHex(conversationKey(key(vector.sec1), vector.pub2))).toBe(
        vector.conversation_key,
      )
    }
    expect(v2.valid.get_conversation_key.length).toBeGreaterThan(0)
  })

  it('refuses every invalid vector', () => {
    // Includes points on the twist and secrets at or past the curve order —
    // the cases where a permissive ECDH yields a key rather than an error.
    for (const vector of v2.invalid.get_conversation_key) {
      expect(() => conversationKey(key(vector.sec1), vector.pub2), vector.note).toThrow()
    }
    expect(v2.invalid.get_conversation_key.length).toBeGreaterThan(0)
  })
})

describe('message keys', () => {
  it('splits the HKDF output the way every vector expects', () => {
    const conversation = hexToBytes(v2.valid.get_message_keys.conversation_key)
    for (const vector of v2.valid.get_message_keys.keys) {
      const keys = messageKeys(conversation, hexToBytes(vector.nonce))
      expect(bytesToHex(keys.chachaKey)).toBe(vector.chacha_key)
      expect(bytesToHex(keys.chachaNonce)).toBe(vector.chacha_nonce)
      expect(bytesToHex(keys.hmacKey)).toBe(vector.hmac_key)
    }
    expect(v2.valid.get_message_keys.keys.length).toBeGreaterThan(0)
  })
})

describe('padding', () => {
  it('matches every calc_padded_len vector', () => {
    for (const [unpadded, padded] of v2.valid.calc_padded_len) {
      expect(calcPaddedLen(unpadded), `padded length of ${unpadded}`).toBe(padded)
    }
  })
})

describe('encrypt and decrypt', () => {
  it('reproduces every vector payload byte for byte', () => {
    // The nonce is supplied, so our output is comparable to theirs — the only
    // way to catch a padding or HKDF divergence that still round-trips locally.
    for (const vector of v2.valid.encrypt_decrypt) {
      const conversation = conversationKey(key(vector.sec1), bytesToHex(pubkeyOf(vector.sec2)))
      expect(bytesToHex(conversation)).toBe(vector.conversation_key)
      expect(encrypt(vector.plaintext, conversation, hexToBytes(vector.nonce))).toBe(vector.payload)
      expect(decrypt(vector.payload, conversation)).toBe(vector.plaintext)
    }
  })

  it('reproduces the long-message vectors', () => {
    for (const vector of v2.valid.encrypt_decrypt_long_msg) {
      const conversation = hexToBytes(vector.conversation_key)
      const plaintext = vector.pattern.repeat(vector.repeat)
      expect(bytesToHex(sha256(utf8ToBytes(plaintext)))).toBe(vector.plaintext_sha256)

      const payload = encrypt(plaintext, conversation, hexToBytes(vector.nonce))
      expect(bytesToHex(sha256(utf8ToBytes(payload)))).toBe(vector.payload_sha256)
      expect(decrypt(payload, conversation)).toBe(plaintext)
    }
  })

  it('refuses every invalid payload', () => {
    for (const vector of v2.invalid.decrypt) {
      expect(
        () => decrypt(vector.payload, hexToBytes(vector.conversation_key)),
        vector.note,
      ).toThrow(Nip44Error)
    }
  })

  it('refuses plaintext lengths outside 1..65535 bytes', () => {
    const conversation = hexToBytes(v2.valid.encrypt_decrypt[0]?.conversation_key ?? '')
    for (const length of v2.invalid.encrypt_msg_lengths) {
      expect(() => encrypt('a'.repeat(length), conversation), `length ${length}`).toThrow(
        Nip44Error,
      )
    }
  })

  it('counts bytes rather than characters at the upper bound', () => {
    // A multi-byte character makes `plaintext.length` and the padded length
    // disagree, which is where a naive bound check admits an over-long message.
    const conversation = hexToBytes(v2.valid.encrypt_decrypt[0]?.conversation_key ?? '')
    const justOver = '🦄'.repeat(MAX_PLAINTEXT_BYTES / 4 + 1)
    expect(justOver.length).toBeLessThan(MAX_PLAINTEXT_BYTES)
    expect(() => encrypt(justOver, conversation)).toThrow(Nip44Error)
  })

  it('round-trips with a random nonce', () => {
    const conversation = hexToBytes(v2.valid.encrypt_decrypt[0]?.conversation_key ?? '')
    const payload = encrypt('read state', conversation)
    expect(payload).not.toBe(encrypt('read state', conversation))
    expect(decrypt(payload, conversation)).toBe('read state')
  })
})
