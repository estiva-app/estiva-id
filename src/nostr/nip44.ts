/**
 * NIP-44 v2 encryption.
 *
 * A local implementation, like `event.ts` and `nip98.ts` — apps sharing no code
 * is the property being demonstrated (PEEK-25). Unlike those two, none of the
 * arithmetic here is a judgement call: the padding scheme, the key derivation
 * and the MAC's AAD are all exactly specified, and getting any of them subtly
 * wrong produces ciphertext that looks fine and is not interoperable.
 *
 * So this file is written against the **official test vectors** rather than
 * against prose, and `nip44.test.ts` runs all 108 of them, valid and invalid,
 * from `nip44.vectors.json` (github.com/paulmillr/nip44, the reference suite the
 * NIP itself points at). Any divergence in padding, HKDF info or MAC ordering
 * fails there rather than in production against another implementation.
 *
 * The construction, in order:
 *
 *   1. `conversation_key = hkdf_extract(IKM = ecdh_x, salt = "nip44-v2")`
 *   2. `hkdf_expand(conversation_key, info = nonce, 76)` splits into a
 *      ChaCha20 key (32), a ChaCha20 nonce (12) and an HMAC key (32)
 *   3. plaintext is length-prefixed and padded to a power-of-two-ish bucket, so
 *      ciphertext length leaks a bucket rather than a byte count
 *   4. `HMAC-SHA256(hmac_key, nonce || ciphertext)` — the nonce is AAD, and it
 *      is *prepended*, not appended
 *   5. payload = base64(`0x02` || nonce || ciphertext || mac)
 *
 * **Not interchangeable with NIP-04**, which has no MAC at all. There is
 * deliberately no NIP-04 fallback path in this file.
 */
import { chacha20 } from '@noble/ciphers/chacha.js'
import { secp256k1 } from '@noble/curves/secp256k1'
import { expand as hkdfExpand, extract as hkdfExtract } from '@noble/hashes/hkdf'
import { hmac } from '@noble/hashes/hmac'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToUtf8, concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils'

/** The only version this file writes, and the only one it reads. */
export const NIP44_VERSION = 2

/** Plaintext bounds, in bytes of UTF-8 — not characters. */
export const MIN_PLAINTEXT_BYTES = 1
export const MAX_PLAINTEXT_BYTES = 65535

/**
 * A conversation key is 32 bytes of HKDF output, not a shared secret directly.
 * Branded so a raw ECDH result cannot be passed where one is expected.
 */
export type ConversationKey = Uint8Array

/** Thrown for every refusal here, so a caller can tell a NIP-44 fault from a bug. */
export class Nip44Error extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'Nip44Error'
  }
}

/**
 * `nip44_conversation_key(privkey_a, pubkey_b)`.
 *
 * The ECDH output's **x coordinate only** — the 33-byte compressed point minus
 * its parity byte. Feeding the whole point in is the classic way to produce a
 * key that works perfectly against yourself and against nobody else.
 *
 * Self-encryption (CRO-1) is this called with a key's own public half, which is
 * a legitimate ECDH and needs no special case.
 */
export function conversationKey(secretKey: Uint8Array, publicKeyHex: string): ConversationKey {
  let sharedPoint: Uint8Array
  try {
    // x-only pubkeys are stored throughout this service; `02` is the parity
    // prefix NIP-44 specifies for lifting one back to a point.
    sharedPoint = secp256k1.getSharedSecret(secretKey, `02${publicKeyHex}`)
  } catch (error) {
    throw new Nip44Error(`invalid public key: ${(error as Error).message}`)
  }
  return hkdfExtract(sha256, sharedPoint.subarray(1, 33), utf8ToBytes('nip44-v2'))
}

export interface MessageKeys {
  chachaKey: Uint8Array
  chachaNonce: Uint8Array
  hmacKey: Uint8Array
}

/**
 * Split one HKDF-expand output into the three keys a message needs.
 *
 * Exported for `nip44.test.ts`, which pins all 32 `get_message_keys` vectors.
 * The `encrypt` vectors cover this derivation implicitly, but a wrong split
 * shows up there as "the whole payload differs" — here it says which of the
 * three ranges moved.
 */
export function messageKeys(conversation: ConversationKey, nonce: Uint8Array): MessageKeys {
  if (conversation.length !== 32) throw new Nip44Error('invalid conversation key length')
  if (nonce.length !== 32) throw new Nip44Error('invalid nonce length')
  const keys = hkdfExpand(sha256, conversation, nonce, 76)
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76),
  }
}

/**
 * The padded length for `unpaddedLen` bytes.
 *
 * Deliberately bit arithmetic rather than `Math.log2`: at exact powers of two a
 * float log is one ulp from the wrong integer, and the failure would be a
 * padded length that differs from every other implementation only for certain
 * message sizes. `31 - Math.clz32(n)` is `floor(log2(n))` exactly.
 */
export function calcPaddedLen(unpaddedLen: number): number {
  if (unpaddedLen < 1) throw new Nip44Error('expected positive integer')
  if (unpaddedLen <= 32) return 32
  const nextPower = 1 << (31 - Math.clz32(unpaddedLen - 1) + 1)
  const chunk = nextPower <= 256 ? 32 : nextPower / 8
  return chunk * (Math.floor((unpaddedLen - 1) / chunk) + 1)
}

function pad(plaintext: string): Uint8Array {
  const unpadded = utf8ToBytes(plaintext)
  const unpaddedLen = unpadded.length
  if (unpaddedLen < MIN_PLAINTEXT_BYTES || unpaddedLen > MAX_PLAINTEXT_BYTES) {
    throw new Nip44Error(`invalid plaintext length: ${unpaddedLen}`)
  }
  const prefix = new Uint8Array(2)
  new DataView(prefix.buffer).setUint16(0, unpaddedLen, false)
  const suffix = new Uint8Array(calcPaddedLen(unpaddedLen) - unpaddedLen)
  return concatBytes(prefix, unpadded, suffix)
}

function unpad(padded: Uint8Array): string {
  if (padded.length < 2) throw new Nip44Error('invalid padding')
  const unpaddedLen = new DataView(padded.buffer, padded.byteOffset, padded.byteLength).getUint16(
    0,
    false,
  )
  const unpadded = padded.subarray(2, 2 + unpaddedLen)
  if (
    unpaddedLen < MIN_PLAINTEXT_BYTES ||
    unpaddedLen > MAX_PLAINTEXT_BYTES ||
    unpadded.length !== unpaddedLen ||
    padded.length !== 2 + calcPaddedLen(unpaddedLen)
  ) {
    throw new Nip44Error('invalid padding')
  }
  return bytesToUtf8(unpadded)
}

/** The nonce is AAD and is **prepended** to the ciphertext before hashing. */
function hmacWithAad(key: Uint8Array, message: Uint8Array, aad: Uint8Array): Uint8Array {
  if (aad.length !== 32) throw new Nip44Error('AAD associated data must be 32 bytes')
  return hmac(sha256, key, concatBytes(aad, message))
}

/**
 * Constant-time comparison.
 *
 * A MAC check that returns early on the first differing byte is a timing oracle
 * for forging one, so the loop always runs to the end.
 */
function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number)
  return diff === 0
}

/** Base64 payload bounds, from the spec. Checked before decoding, not after. */
const MIN_PAYLOAD_CHARS = 132
const MAX_PAYLOAD_CHARS = 87472

/**
 * Strict base64.
 *
 * `Buffer.from(s, 'base64')` silently skips characters outside the alphabet, so
 * a corrupted payload would decode to *something* and then fail later with a
 * misleading MAC error. The vectors include exactly that case.
 */
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/

function decodeBase64(payload: string): Uint8Array {
  if (payload.length % 4 !== 0 || !BASE64.test(payload)) {
    throw new Nip44Error('invalid base64')
  }
  return new Uint8Array(Buffer.from(payload, 'base64'))
}

/** Encrypt `plaintext` under an already-derived conversation key. */
export function encrypt(
  plaintext: string,
  conversation: ConversationKey,
  nonce: Uint8Array = randomBytes(32),
): string {
  const keys = messageKeys(conversation, nonce)
  const ciphertext = chacha20(keys.chachaKey, keys.chachaNonce, pad(plaintext))
  const mac = hmacWithAad(keys.hmacKey, ciphertext, nonce)
  return Buffer.from(concatBytes(new Uint8Array([NIP44_VERSION]), nonce, ciphertext, mac)).toString(
    'base64',
  )
}

/** Decrypt a v2 payload. Throws {@link Nip44Error} on any malformed input. */
export function decrypt(payload: string, conversation: ConversationKey): string {
  if (payload.length < MIN_PAYLOAD_CHARS || payload.length > MAX_PAYLOAD_CHARS) {
    throw new Nip44Error(`invalid payload length: ${payload.length}`)
  }
  // NIP-04 payloads and future versions are announced by a leading `#`, and the
  // spec asks for this check before base64 is even attempted.
  if (payload.startsWith('#')) throw new Nip44Error('unknown encryption version')

  const data = decodeBase64(payload)
  if (data.length < 99 || data.length > 65603) {
    throw new Nip44Error(`invalid data length: ${data.length}`)
  }

  const version = data[0]
  if (version !== NIP44_VERSION) throw new Nip44Error(`unknown encryption version ${version}`)

  const nonce = data.subarray(1, 33)
  const ciphertext = data.subarray(33, data.length - 32)
  const mac = data.subarray(data.length - 32)

  const keys = messageKeys(conversation, nonce)
  if (!equalBytes(hmacWithAad(keys.hmacKey, ciphertext, nonce), mac)) {
    throw new Nip44Error('invalid MAC')
  }
  return unpad(chacha20(keys.chachaKey, keys.chachaNonce, ciphertext))
}
