/**
 * Key-encryption key resolution.
 *
 * One deployment key in Stage 1, looked up by `kid`. The indirection is the
 * point: Stage 4 replaces this resolver with one that reaches a KMS or a set of
 * escrow custodians, and no call site changes.
 */
import { config } from '../config.js'
import type { KekResolver } from '../crypto/envelope.js'

export function currentKid(): string {
  return config().KEY_ENCRYPTION_KID
}

export function currentKek(): Buffer {
  return Buffer.from(config().KEY_ENCRYPTION_KEK, 'hex')
}

/**
 * Resolve a KEK by id.
 *
 * Returns undefined for unknown ids rather than falling back to the current
 * key — an envelope wrapped under a retired key must fail loudly, not decrypt
 * under the wrong one.
 */
export const resolveKek: KekResolver = (kid) => (kid === currentKid() ? currentKek() : undefined)
