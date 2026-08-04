/**
 * secp256k1 keypairs and schnorr signing.
 *
 * Custody is a deliberate trade at this stage: holding the secret is what makes
 * `/sign` and account recovery possible at all. It also means the service can
 * sign as anyone, so **nothing signed here may be presented to users as
 * cryptographic proof of authorship** until Stage 4 moves keys out of custody.
 *
 * Secrets exist in memory only for the duration of a signature, and are zeroed
 * afterwards. That is not a defence against a compromised host — it narrows the
 * window in heap dumps and core files, nothing more.
 */
import { schnorr } from '@noble/curves/secp256k1'
import { bytesToHex } from '@noble/hashes/utils'
import { type SignedEvent, type UnsignedEvent, computeEventId } from './event.js'

export interface Keypair {
  /** x-only public key, 64 lowercase hex characters. */
  publicKeyHex: string
  /** Raw 32-byte secret. Encrypt before storing; never return over an API. */
  secretKey: Buffer
}

export function generateKeypair(): Keypair {
  const secretKey = Buffer.from(schnorr.utils.randomPrivateKey())
  return { publicKeyHex: bytesToHex(schnorr.getPublicKey(secretKey)), secretKey }
}

export function publicKeyFromSecret(secretKey: Buffer): string {
  return bytesToHex(schnorr.getPublicKey(secretKey))
}

/**
 * Sign an event.
 *
 * The `pubkey` on the event is **not trusted** — it is overwritten with the one
 * derived from the secret, and the id is recomputed over the result. A caller
 * therefore cannot ask for a signature attributed to somebody else, whatever it
 * puts in the request body.
 */
export function signEvent(unsigned: UnsignedEvent, secretKey: Buffer): SignedEvent {
  const pubkey = publicKeyFromSecret(secretKey)
  const authoritative: UnsignedEvent = { ...unsigned, pubkey }
  const id = computeEventId(authoritative)
  const sig = bytesToHex(schnorr.sign(id, secretKey))
  return { ...authoritative, id, sig }
}

export function verifyEvent(event: SignedEvent): boolean {
  if (computeEventId(event) !== event.id) return false
  try {
    return schnorr.verify(event.sig, event.id, event.pubkey)
  } catch {
    return false
  }
}
