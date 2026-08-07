/**
 * Reading Estiva Peek's custodied keys (PEEK-37).
 *
 * Peek encrypts each secret with AES-256-GCM under `sha256(passphrase)` and
 * stores base64 of `iv || ciphertext || tag` — see its `convex/nostr/keys.ts`.
 * That sha256 is not a password KDF, and was not meant to be: the input was
 * expected to be high-entropy already. Reproduced faithfully rather than
 * improved, because the job here is to decrypt what that code encrypted.
 *
 * Lives in `src/` rather than in the migration script so the guard below is
 * covered by the test suite. It is the one piece of this whose failure is
 * unrecoverable, and it would otherwise never run until the day it mattered.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { sha256 } from '@noble/hashes/sha256'
import { publicKeyFromSecret } from '../nostr/keys.js'

const IV_BYTES = 12
const TAG_BYTES = 16

function keyFromPassphrase(passphrase: string): Buffer {
  return Buffer.from(sha256(new TextEncoder().encode(passphrase)))
}

/** Decrypt one of Peek's stored secrets. Throws if the passphrase is wrong. */
export function decryptPeekSecret(stored: string, passphrase: string): Buffer {
  const packed = Buffer.from(stored, 'base64')
  if (packed.length <= IV_BYTES + TAG_BYTES) {
    throw new Error('ciphertext too short to be a valid Peek blob')
  }

  const iv = packed.subarray(0, IV_BYTES)
  const body = packed.subarray(IV_BYTES, packed.length - TAG_BYTES)
  const tag = packed.subarray(packed.length - TAG_BYTES)

  const decipher = createDecipheriv('aes-256-gcm', keyFromPassphrase(passphrase), iv)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}

/** Peek's format, for building fixtures. Not used by the migration itself. */
export function encryptPeekSecret(secret: Buffer, passphrase: string): string {
  const iv = randomBytes(IV_BYTES)
  const cipher = createCipheriv('aes-256-gcm', keyFromPassphrase(passphrase), iv)
  const body = Buffer.concat([cipher.update(secret), cipher.final()])
  return Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64')
}

export type PairCheck =
  | { ok: true; pubkey: string }
  | { ok: false; reason: 'mismatch'; derived: string; claimed: string }

/**
 * Confirm a decrypted secret really belongs to the pubkey Peek claimed.
 *
 * **This is the check the migration exists for.** A key written under the wrong
 * pubkey is worse than one that fails to arrive: the account still works, still
 * signs, and everything the person published beforehand silently detaches from
 * them — noticed months later, if at all. Refusing is always the better answer.
 *
 * It also catches a wrong passphrase that happens to decrypt, a corrupted blob,
 * and a row whose pubkey and secret were never a pair to begin with.
 */
export function checkPair(secret: Buffer, claimedPubkey: string): PairCheck {
  const derived = publicKeyFromSecret(secret)
  if (derived !== claimedPubkey.toLowerCase()) {
    return { ok: false, reason: 'mismatch', derived, claimed: claimedPubkey }
  }
  return { ok: true, pubkey: derived }
}
