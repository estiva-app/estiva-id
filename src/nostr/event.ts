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

/** kind:0 — the profile metadata event. */
export const KIND_PROFILE = 0

export interface ProfileFields {
  display_name?: string
  /** Written alongside `display_name` — see below on why both. */
  name?: string
  picture?: string
  about?: string
  nip05?: string
}

/**
 * Build a kind:0 profile event (PEEK-31).
 *
 * Two details decide whether this works, and both are easy to get wrong:
 *
 * **Key order is alphabetical.** Buzz builds profile content with
 * `serde_json::Map`, which is a `BTreeMap` unless the `preserve_order` feature
 * is enabled — and it is not enabled in Buzz's workspace. So keys serialize as
 * about, display_name, name, nip05, picture. Content is a *string* inside the
 * event, and the event id is a hash over it, so a different order is a
 * different id for the same profile.
 *
 * **A field that is absent is a field that is cleared.** Omitting `nip05`
 * revokes the handle, and so does an empty string — measured against the live
 * relay (`estiva-ship` 63cd32d), which contradicted what reading
 * `buzz-db/src/user.rs` suggested. That is what makes offboarding a publish
 * rather than a special case, and it is why empty values are dropped here
 * instead of being sent through: both spellings mean the same thing to the
 * relay, so only one is ever emitted.
 *
 * `name` and `display_name` are both written because consumers read either —
 * older events carry both, and dropping one makes a person render as their
 * pubkey in whichever app happens to read the other.
 */
export function buildProfile(
  pubkey: string,
  createdAtSeconds: number,
  fields: ProfileFields,
): UnsignedEvent {
  const present = Object.entries(fields).filter(([, value]) => value !== undefined && value !== '')
  present.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  const content = `{${present
    .map(([key, value]) => `${JSON.stringify(key)}:${JSON.stringify(value)}`)
    .join(',')}}`
  return { pubkey, created_at: createdAtSeconds, kind: KIND_PROFILE, tags: [], content }
}
