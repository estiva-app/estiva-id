/**
 * NIP-01 event construction.
 *
 * Deliberately a local implementation rather than a shared package. Estiva Peek
 * has its own copy in `convex/nostr/events.ts` and Linear-lite has another; that
 * duplication is the architecture, not an oversight. "Apps sharing no code and
 * no database work on the same data" stops being demonstrable the moment they
 * agree by importing the same module (PEEK-25).
 */
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils'

/** A Nostr tag: an array of strings whose first element is the tag name. */
export type NostrTag = string[]

export interface UnsignedEvent {
  pubkey: string
  created_at: number
  kind: number
  tags: NostrTag[]
  content: string
}

export interface SignedEvent extends UnsignedEvent {
  id: string
  sig: string
}

export const HEX64 = /^[0-9a-f]{64}$/

/**
 * NIP-01 event id: sha256 over the canonical serialization
 * `[0, pubkey, created_at, kind, tags, content]`.
 *
 * `JSON.stringify` produces exactly the escaping NIP-01 requires (`\n`, `\"`,
 * `\\`, `\r`, `\t`, `\b`, `\f`, `\uXXXX` for other control characters) with no
 * insignificant whitespace, so no custom serializer is needed.
 */
export function computeEventId(event: UnsignedEvent): string {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ])
  return bytesToHex(sha256(utf8ToBytes(serialized)))
}

/** Value of the first tag with the given name, if present. */
export function tagValue(event: UnsignedEvent, name: string): string | undefined {
  return event.tags.find((tag) => tag[0] === name)?.[1]
}
