/**
 * NIP-98 HTTP auth for Buzz's REST bridge.
 *
 * The bridge (`POST /events`, `POST /query`) authenticates with NIP-98, **not**
 * NIP-42 — no challenge/response and no persistent connection, so publishing a
 * profile is one request rather than a connection lifecycle.
 *
 * Ported from Peek's `convex/nostr/nip98.ts`, which was written against the
 * relay's verifier (`verify_nip98_event`, crates/buzz-auth/src/nip98.rs:55)
 * rather than inferred. Its rules, in order:
 *
 *   1. kind must be 27235
 *   2. valid Schnorr signature + id hash
 *   3. `created_at` within ±60s of the relay's clock
 *   4. `u` tag must equal the expected URL after normalization
 *   5. `method` tag must match (case-insensitive)
 *   6. if a `payload` tag is present AND a body was sent, sha256(body) must match
 *
 * This is a second copy on purpose, the same way `event.ts` is: apps sharing no
 * code is the property being demonstrated (PEEK-25). The duplication is the
 * architecture, not an oversight.
 */
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils'
import type { NostrTag, SignedEvent, UnsignedEvent } from './event.js'
import { signEvent } from './keys.js'

/** NIP-98 HTTP auth. */
export const KIND_HTTP_AUTH = 27235

/** The relay rejects auth events outside ±60s (`TIMESTAMP_TOLERANCE_SECS`). */
export const TIMESTAMP_TOLERANCE_SECS = 60

/**
 * Buzz's `normalize_url` (nip98.rs:145): parse, strip trailing slashes from the
 * path, re-serialize. We only need it to keep our own `u` tag canonical.
 */
export function normalizeUrl(raw: string): string {
  try {
    const parsed = new URL(raw)
    parsed.pathname = parsed.pathname.replace(/\/+$/, '')
    return parsed.toString()
  } catch {
    return raw.toLowerCase()
  }
}

export interface AuthEventArgs {
  secretKey: Buffer
  /** Full request URL, with the same host the relay will see. */
  url: string
  method: string
  /** Request body, when there is one — adds the `payload` tag. */
  body?: string
  /** Override for tests; defaults to now. */
  nowMs?: number
  /** Override for tests; defaults to random. Must differ per request. */
  nonce?: string
}

/**
 * Build the signed kind:27235 event backing an `Authorization: Nostr …` header.
 *
 * `url` must be the full request URL with the same host the relay will see —
 * `nip98_expected_url` (bridge.rs:195) reconstructs it as
 * `{http|https}://{host}{path}` from the request's own Host header, and there
 * is no loopback aliasing: `localhost`, `127.0.0.1` and `::1` are distinct
 * hosts to the verifier.
 */
export function buildAuthEvent(args: AuthEventArgs): SignedEvent {
  const tags: NostrTag[] = [
    ['u', normalizeUrl(args.url)],
    ['method', args.method.toUpperCase()],
    // Uniqueness, not security. Each auth event id is recorded in a Redis
    // seen-set (`check_nip98_replay`, bridge.rs:135), and `created_at` has
    // one-second resolution — so two requests with the same URL, method and
    // body inside the same second produce a byte-identical event and the
    // second is refused with `NIP-98: replay detected`. Republishing an
    // unchanged profile twice in a second is exactly that case. The verifier
    // looks tags up by name and ignores ones it does not know, so this is safe.
    ['nonce', args.nonce ?? bytesToHex(randomBytes(16))],
  ]
  if (args.body !== undefined) {
    tags.push(['payload', bytesToHex(sha256(utf8ToBytes(args.body)))])
  }
  const unsigned: UnsignedEvent = {
    // Overwritten by signEvent from the secret; present to satisfy the type.
    pubkey: '',
    created_at: Math.floor((args.nowMs ?? Date.now()) / 1000),
    kind: KIND_HTTP_AUTH,
    tags,
    content: '',
  }
  return signEvent(unsigned, args.secretKey)
}

/**
 * The full header value: `Nostr <base64(signed kind-27235 event JSON)>`
 * (bridge.rs:81-93 strips the `Nostr ` prefix and base64-decodes the rest).
 */
export function authorizationHeader(args: AuthEventArgs): string {
  return `Nostr ${Buffer.from(JSON.stringify(buildAuthEvent(args)), 'utf8').toString('base64')}`
}
