/**
 * The at-rest encryption envelope for anything this service can sign with.
 *
 * PEEK-27: *"Design the storage format for M-of-N escrow now, even though
 * Stage 1 ships a single deployment key. That is a format decision, not a
 * feature, and retrofitting it later is a migration."* This file is that
 * format.
 *
 * ## Shape
 *
 * Two layers, always:
 *
 *   1. The secret is encrypted once under a **random per-secret DEK**
 *      (AES-256-GCM).
 *   2. The DEK is distributed as one or more **shares**, each encrypted under a
 *      key-encryption key identified by `kid`.
 *
 * Stage 1 writes `scheme: 'direct'` with a single share holding the whole DEK,
 * wrapped under the deployment KEK. Stage 4 can write `scheme: 'shamir'` with
 * `threshold: M` and N shares held by different custodians — **without
 * re-encrypting a single user secret**, because the ciphertext layer never
 * changes. Adding a custodian is rewriting a small JSON field; it is not a
 * migration over every key in the table.
 *
 * The two-layer split is the whole point. Wrapping the secret directly under
 * the deployment key — which is what Estiva Peek's `convex/nostr/keys.ts` does
 * today — means every future custody change re-encrypts every secret, and there
 * is nowhere to put a second custodian. That is the trap this avoids.
 *
 * ## Why threshold and not just "several wraps"
 *
 * N independent wraps of the same DEK is 1-of-N: *any single* holder can
 * decrypt. That is the opposite of escrow. Real M-of-N needs the DEK split into
 * shares that must be recombined, so the format carries `scheme` and
 * `threshold` from v1 rather than pretending a list of wraps is enough.
 *
 * ## AAD
 *
 * The ciphertext is bound to the row that owns it. Moving an envelope onto
 * another user's row makes decryption fail rather than silently signing as the
 * wrong person — which matters precisely because this service is custodial.
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'

export const ENVELOPE_VERSION = 1 as const

const CIPHER = 'aes-256-gcm' as const
const IV_BYTES = 12
const TAG_BYTES = 16
const DEK_BYTES = 32
const SALT_BYTES = 16
const HKDF_INFO = 'estiva-id/envelope/kek-wrap/v1'

/** One encrypted piece of the DEK, held under a single key-encryption key. */
export interface EnvelopeShare {
  /** Identifies which KEK wraps this share. Rotation and escrow both key off it. */
  kid: string
  alg: 'AES-256-GCM'
  /** HKDF salt for deriving the wrapping key from the KEK. Base64. */
  salt: string
  iv: string
  /** Ciphertext of the DEK (`direct`) or of one Shamir share (`shamir`). Base64. */
  ct: string
}

export interface EnvelopeDek {
  /**
   * `direct` — one share carrying the whole DEK. Stage 1.
   * `shamir` — Shamir shares of the DEK; `threshold` of them reconstruct it.
   *            Reserved for Stage 4; `openEnvelope` rejects it rather than
   *            guessing at a combiner that does not exist yet.
   */
  scheme: 'direct' | 'shamir'
  threshold: number
  shares: EnvelopeShare[]
}

/** Additional authenticated data — binds the ciphertext to its owning row. */
export type EnvelopeAad = Record<string, string>

export interface Envelope {
  v: typeof ENVELOPE_VERSION
  cipher: 'AES-256-GCM'
  iv: string
  /** Ciphertext with the GCM tag appended. Base64. */
  ct: string
  aad: EnvelopeAad
  dek: EnvelopeDek
  createdAt: string
}

/**
 * Resolves a key-encryption key by id.
 *
 * A function rather than a value so a KMS, an HSM or a set of escrow custodians
 * can be dropped in later without touching call sites.
 */
export type KekResolver = (kid: string) => Buffer | undefined

const b64 = (buf: Buffer): string => buf.toString('base64')
const unb64 = (value: string): Buffer => Buffer.from(value, 'base64')

/** AAD is canonicalised so encrypt and decrypt agree regardless of key order. */
function encodeAad(aad: EnvelopeAad): Buffer {
  const canonical = Object.keys(aad)
    .sort()
    .map((key) => `${key}=${aad[key]}`)
    .join('&')
  return Buffer.from(canonical, 'utf8')
}

function deriveWrappingKey(kek: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', kek, salt, Buffer.from(HKDF_INFO, 'utf8'), 32))
}

function encrypt(key: Buffer, plaintext: Buffer, aad?: Buffer): { iv: Buffer; ct: Buffer } {
  const iv = randomBytes(IV_BYTES)
  const cipher = createCipheriv(CIPHER, key, iv)
  if (aad) cipher.setAAD(aad)
  const body = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return { iv, ct: Buffer.concat([body, cipher.getAuthTag()]) }
}

function decrypt(key: Buffer, iv: Buffer, ct: Buffer, aad?: Buffer): Buffer {
  if (ct.length < TAG_BYTES) throw new Error('ciphertext too short to contain a GCM tag')
  const body = ct.subarray(0, ct.length - TAG_BYTES)
  const tag = ct.subarray(ct.length - TAG_BYTES)
  const decipher = createDecipheriv(CIPHER, key, iv)
  if (aad) decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}

export interface SealOptions {
  secret: Buffer
  aad: EnvelopeAad
  kek: Buffer
  kid: string
}

/**
 * Encrypt a secret into a v1 envelope under a single deployment KEK.
 *
 * The DEK is generated here and never leaves this function in the clear.
 */
export function sealEnvelope({ secret, aad, kek, kid }: SealOptions): Envelope {
  if (kek.length !== 32) throw new Error('KEK must be 32 bytes')

  const dek = randomBytes(DEK_BYTES)
  const aadBytes = encodeAad(aad)
  const sealed = encrypt(dek, secret, aadBytes)

  const salt = randomBytes(SALT_BYTES)
  const wrapped = encrypt(deriveWrappingKey(kek, salt), dek)
  // The DEK has been copied into the ciphertext; drop the plaintext copy.
  dek.fill(0)

  return {
    v: ENVELOPE_VERSION,
    cipher: 'AES-256-GCM',
    iv: b64(sealed.iv),
    ct: b64(sealed.ct),
    aad,
    dek: {
      scheme: 'direct',
      threshold: 1,
      shares: [
        { kid, alg: 'AES-256-GCM', salt: b64(salt), iv: b64(wrapped.iv), ct: b64(wrapped.ct) },
      ],
    },
    createdAt: new Date().toISOString(),
  }
}

export interface OpenOptions {
  envelope: Envelope
  aad: EnvelopeAad
  resolveKek: KekResolver
}

/**
 * Decrypt an envelope.
 *
 * `aad` is supplied by the caller from the row it read, not taken from the
 * envelope itself — otherwise the binding proves nothing, since an attacker who
 * can move the envelope can move its `aad` too.
 */
export function openEnvelope({ envelope, aad, resolveKek }: OpenOptions): Buffer {
  if (envelope.v !== ENVELOPE_VERSION) {
    throw new Error(`Unsupported envelope version ${envelope.v}`)
  }
  if (envelope.dek.scheme === 'shamir') {
    // Stage 4 supplies the combiner. Failing loudly beats a plausible-looking
    // wrong answer about who can decrypt what.
    throw new Error('Shamir-shared envelopes are not supported yet (Stage 4)')
  }
  if (envelope.dek.scheme !== 'direct') {
    throw new Error(`Unsupported DEK scheme ${envelope.dek.scheme}`)
  }

  const share = envelope.dek.shares.find((candidate) => resolveKek(candidate.kid) !== undefined)
  if (!share) {
    const known = envelope.dek.shares.map((s) => s.kid).join(', ')
    throw new Error(`No available key-encryption key for this envelope (needs one of: ${known})`)
  }

  const kek = resolveKek(share.kid)
  if (!kek) throw new Error(`KEK ${share.kid} disappeared between lookup and use`)

  const dek = decrypt(deriveWrappingKey(kek, unb64(share.salt)), unb64(share.iv), unb64(share.ct))
  try {
    return decrypt(dek, unb64(envelope.iv), unb64(envelope.ct), encodeAad(aad))
  } finally {
    dek.fill(0)
  }
}

/** Which KEKs an envelope can currently be opened with. Useful for rotation reporting. */
export function envelopeKids(envelope: Envelope): string[] {
  return envelope.dek.shares.map((share) => share.kid)
}
