/**
 * Blossom reads and writes against the relay's media store (PEEK-32, SHA-22).
 *
 * An avatar has to live somewhere that outlives the app that set it. Stage 0
 * published a Convex storage URL, which ties an ecosystem-wide profile picture
 * to one deployment's lifetime — when that Convex project goes, every avatar in
 * every app breaks. Content-addressed and workspace-owned is the right owner.
 *
 * ## This is not NIP-98
 *
 * The bridge (`POST /events`) authenticates with NIP-98 kind:27235. The media
 * store does **not** — it is Blossom BUD-11, kind:24242, with different rules and
 * a different failure mode. Reusing `nip98.ts` here fails with `InvalidAuthKind`.
 *
 * Every rule below is read from Buzz's verifier
 * (`crates/buzz-media/src/auth.rs`, `crates/buzz-relay/src/api/media.rs`) rather
 * than from the spec, because two of them are not in BUD-11 and one is not in
 * the ticket:
 *
 *   1. `kind` is 24242.
 *   2. **`content` must be non-empty** — a "human readable string". An empty
 *      one is `InvalidAuthEvent`, which is not obvious from the spec.
 *   3. `t` tag equals the verb — `upload` to store, `get` to read.
 *   4. `expiration` tag is **required** and must be in the future.
 *   5. `created_at` is recent: no more than 5s ahead, and no older than the
 *      server's window — 3600s at the door, then **re-checked at 600s for
 *      images** once the MIME type is known. So an auth event that passes the
 *      outer check can still be refused later; keep it freshly minted.
 *   6. At least one `x` tag equals the body's sha256, lowercase hex.
 *   7. If any `server` tag is present, this host must be among them.
 *   8. **`X-SHA-256` is a mandatory request header**, 64 lowercase hex, and must
 *      match one of the `x` tags. That is BUD-11's rule and it is not in the
 *      ticket; without the header the upload is refused before the body is read.
 *
 * ## Membership still applies
 *
 * The relay checks `enforce_relay_membership` on upload, before consuming the
 * body. A pubkey nobody has admitted cannot store an avatar, exactly as it
 * cannot publish a profile — see the closed-relay note in the deploy docs. The
 * two failures are distinguishable and that distinction is load-bearing here:
 *
 * | Outcome | Status |
 * | --- | --- |
 * | anything wrong with the auth event | `401` |
 * | auth event fine, pubkey not admitted | `403` |
 *
 * which is what lets a valid client be verified against a live relay without
 * being admitted to it, and without writing anything.
 *
 * ## Reads are authenticated too, and there is no flag left (SHA-22)
 *
 * `GET`/`HEAD /media/*` used to be open, gated by `BUZZ_REQUIRE_MEDIA_GET_AUTH`.
 * Upstream removed the unauthenticated path outright in `fix(media): require
 * authenticated reads` and listed both spellings of the variable as **inert**,
 * so there is nothing an operator can set: production reports relay `0.2.1`,
 * which exists only from that merge onward, and answers a well-formed
 * `/media/<sha256>.jpg` with `401` while a malformed path still gets `404`.
 *
 * A browser cannot satisfy that. `<img src>` sends no headers, and Buzz's
 * `extract_blossom_auth` reads the `Authorization` header only — there is no
 * query-parameter or cookie form of the credential. That is the whole reason
 * every uploaded avatar fell back to initials in Peek and Ship while message
 * attachments kept working: those live in Convex and never touch this store.
 *
 * So the read is signed **here**, where the key already is, and the bytes are
 * proxied — see `domain/avatar.ts`. Two rules differ from the upload path:
 *
 *   - `t` is `get`, and the scope may be either blob-scoped (`x` matches the
 *     hash) or server-scoped (`server` matches the host). We always send both,
 *     so the token is useless for any other blob.
 *   - The window is the outer 3600s one. The 600s image re-check is on the
 *     upload path, where the MIME type is being decided; a read never re-enters
 *     it. Freshly minted anyway, because there is nothing to gain by reusing.
 */
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'
import { config } from '../config.js'
import type { NostrTag, SignedEvent, UnsignedEvent } from './event.js'
import { signEvent } from './keys.js'

/** Blossom authorization. */
export const KIND_BLOSSOM_AUTH = 24242

/**
 * How long the token is valid for.
 *
 * Well inside the 600s window images are re-verified against, because the
 * expiration tag being generous does not help: `created_at` is checked
 * separately and a token that was minted long ago is refused however long it
 * claims to live.
 *
 * The read path is checked against the outer 3600s window only, so this is far
 * more conservative than it needs to be there. It stays one number: a token
 * that is minted, used on the next line and dropped has no use for a longer
 * life, and two TTLs would be two things to keep true.
 */
export const UPLOAD_AUTH_TTL_SECONDS = 120

/** What the media store is being asked to do. Buzz matches the `t` tag exactly. */
export type BlossomVerb = 'upload' | 'get'

export interface BlossomAuthArgs {
  secretKey: Buffer
  /** Lowercase hex sha256 of the exact bytes being uploaded or read. */
  sha256Hex: string
  /**
   * The host the relay resolves this request to, from its own `Host` header —
   * `COMMUNITY_HOST`. Sent as a `server` tag so the token cannot be replayed
   * against a different Blossom server.
   */
  host: string
  /** Override for tests; defaults to now. */
  nowMs?: number
}

export type UploadAuthArgs = BlossomAuthArgs

/**
 * What a human sees if a client ever surfaces the authorization prompt. Buzz
 * refuses an empty `content`, so this is required rather than decorative.
 */
const CONTENT_FOR: Record<BlossomVerb, string> = {
  upload: 'Upload a profile picture to Estiva',
  get: 'Read a profile picture from Estiva',
}

export function buildAuthEvent(verb: BlossomVerb, args: BlossomAuthArgs): SignedEvent {
  const now = Math.floor((args.nowMs ?? Date.now()) / 1000)

  /*
    Both `x` and `server` are sent on both verbs. Buzz's read verifier accepts
    *either* — and a `server`-only token deliberately "grants reads for all
    blobs on the host until expiration", which is far more than this caller
    ever needs. Sending the hash too keeps the token scoped to one blob.
  */
  const tags: NostrTag[] = [
    ['t', verb],
    ['x', args.sha256Hex],
    ['expiration', String(now + UPLOAD_AUTH_TTL_SECONDS)],
    ['server', args.host],
  ]

  const unsigned: UnsignedEvent = {
    // Overwritten by signEvent from the secret; present to satisfy the type.
    pubkey: '',
    created_at: now,
    kind: KIND_BLOSSOM_AUTH,
    tags,
    // Non-empty by requirement, and shown to a human in any client that
    // surfaces authorization prompts — so it says what is being authorised.
    content: CONTENT_FOR[verb],
  }
  return signEvent(unsigned, args.secretKey)
}

export function buildUploadAuthEvent(args: BlossomAuthArgs): SignedEvent {
  return buildAuthEvent('upload', args)
}

/** `Nostr <base64(signed kind-24242 event JSON)>`. */
export function authorizationHeader(verb: BlossomVerb, args: BlossomAuthArgs): string {
  return `Nostr ${Buffer.from(JSON.stringify(buildAuthEvent(verb, args)), 'utf8').toString('base64')}`
}

export function uploadAuthorizationHeader(args: BlossomAuthArgs): string {
  return authorizationHeader('upload', args)
}

/** Buzz's `BlobDescriptor`, as returned by `PUT /media/upload`. */
export interface BlobDescriptor {
  url: string
  sha256: string
  size: number
  /** Serialised as `type`. */
  type: string
  uploaded: number
  dim?: string
  blurhash?: string
  thumb?: string
}

export type UploadResult =
  | { ok: true; blob: BlobDescriptor }
  | {
      ok: false
      /**
       * `not_admitted` is separated from every other refusal because it is the
       * one an operator can fix, and the message a person sees should say so
       * rather than "upload failed".
       */
      reason: 'not_admitted' | 'rejected' | 'unreachable'
      message: string
      httpStatus: number
    }

/**
 * Upload bytes and get back a content-addressed descriptor.
 *
 * The hash is computed here rather than taken from the caller: it has to match
 * the exact bytes sent, and a caller that computes it separately can drift.
 */
export async function uploadBlob(
  bytes: Uint8Array,
  contentType: string,
  secretKey: Buffer,
  options: { signal?: AbortSignal; nowMs?: number } = {},
): Promise<UploadResult> {
  const base = config().RELAY_BRIDGE_URL
  if (!base) throw new Error('RELAY_BRIDGE_URL is not set')

  const host = config().COMMUNITY_HOST
  if (!host) throw new Error('COMMUNITY_HOST is not set')

  const digest = bytesToHex(sha256(bytes))

  let response: Response
  try {
    response = await fetch(`${base}/media/upload`, {
      method: 'PUT',
      headers: {
        'content-type': contentType,
        // Mandatory. Without it the relay answers before reading the body.
        'x-sha-256': digest,
        authorization: uploadAuthorizationHeader({
          secretKey,
          sha256Hex: digest,
          host,
          ...(options.nowMs === undefined ? {} : { nowMs: options.nowMs }),
        }),
      },
      // `BodyInit` does not accept a `Uint8Array<ArrayBufferLike>`; the copy
      // settles the variance rather than casting it away.
      body: new Uint8Array(bytes),
      ...(options.signal ? { signal: options.signal } : {}),
    })
  } catch (error) {
    return {
      ok: false,
      reason: 'unreachable',
      message: error instanceof Error ? error.message : 'Could not reach the media store',
      httpStatus: 0,
    }
  }

  const text = await response.text()

  if (response.status === 403) {
    return {
      ok: false,
      reason: 'not_admitted',
      message: 'This identity has not been admitted to the relay yet',
      httpStatus: 403,
    }
  }

  if (!response.ok) {
    return {
      ok: false,
      reason: 'rejected',
      message: text.slice(0, 200) || `Upload refused (${response.status})`,
      httpStatus: response.status,
    }
  }

  try {
    return { ok: true, blob: JSON.parse(text) as BlobDescriptor }
  } catch {
    return {
      ok: false,
      reason: 'rejected',
      message: `Unparseable descriptor: ${text.slice(0, 200)}`,
      httpStatus: response.status,
    }
  }
}

/**
 * A blob path segment — `<sha256>.<ext>`, or `<sha256>.thumb.jpg`.
 *
 * Buzz builds these itself in `rewrite_descriptor_urls` and validates them
 * again on the way in, so the shape is the relay's, not ours. Matched here so
 * the proxy refuses a hostile segment before it is ever concatenated into a
 * URL — path traversal in a value that becomes a request to another origin is
 * exactly the mistake worth making structurally impossible.
 */
const BLOB_PATH_RE = /^([0-9a-f]{64})\.((?:thumb\.)?[a-z0-9]{1,8})$/

export interface BlobPath {
  sha256: string
  /** Everything after the first dot, `thumb.jpg` included. */
  ext: string
}

/** The parsed blob path, or `null` if this is not one. Never throws. */
export function parseBlobPath(segment: string): BlobPath | null {
  const match = BLOB_PATH_RE.exec(segment)
  return match?.[1] && match[2] ? { sha256: match[1], ext: match[2] } : null
}

export type FetchBlobResult =
  | {
      ok: true
      body: ReadableStream<Uint8Array> | null
      contentType: string
      contentLength: string | null
    }
  | {
      ok: false
      /**
       * `not_found` is the relay's 404 — a hash it does not hold. `not_admitted`
       * is the operator key not being a member, which is the one an operator
       * can fix and must not read as "no such picture". `refused` is anything
       * else the relay said; `unreachable` is ours.
       */
      reason: 'not_found' | 'not_admitted' | 'refused' | 'unreachable'
      message: string
      httpStatus: number
    }

/**
 * Read one blob back out, signing for it.
 *
 * `HEAD` is not offered: the only caller streams the body, and a HEAD would
 * mint a second token to learn what the GET response already carries.
 */
export async function fetchBlob(
  path: BlobPath,
  secretKey: Buffer,
  options: { signal?: AbortSignal; nowMs?: number } = {},
): Promise<FetchBlobResult> {
  const base = config().RELAY_BRIDGE_URL
  if (!base) throw new Error('RELAY_BRIDGE_URL is not set')

  const host = config().COMMUNITY_HOST
  if (!host) throw new Error('COMMUNITY_HOST is not set')

  let response: Response
  try {
    response = await fetch(`${base}/media/${path.sha256}.${path.ext}`, {
      headers: {
        authorization: authorizationHeader('get', {
          secretKey,
          sha256Hex: path.sha256,
          host,
          ...(options.nowMs === undefined ? {} : { nowMs: options.nowMs }),
        }),
      },
      ...(options.signal ? { signal: options.signal } : {}),
    })
  } catch (error) {
    return {
      ok: false,
      reason: 'unreachable',
      message: error instanceof Error ? error.message : 'Could not reach the media store',
      httpStatus: 0,
    }
  }

  if (response.ok) {
    return {
      ok: true,
      body: response.body,
      contentType: response.headers.get('content-type') ?? 'application/octet-stream',
      contentLength: response.headers.get('content-length'),
    }
  }

  // Drained so the connection is not left half-read; never logged as content.
  const text = await response.text().catch(() => '')

  const reason: 'not_found' | 'not_admitted' | 'refused' =
    response.status === 404 ? 'not_found' : response.status === 403 ? 'not_admitted' : 'refused'

  return {
    ok: false,
    reason,
    message: text.slice(0, 200) || `Media read refused (${response.status})`,
    httpStatus: response.status,
  }
}
