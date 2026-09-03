/**
 * Avatars, stored on the relay (PEEK-32).
 *
 * Stage 0 published a Convex storage URL as `picture`, which ties an
 * ecosystem-wide profile picture to one deployment's lifetime: when that project
 * goes, every avatar in every app breaks — including in apps we did not write,
 * which are reading the same `kind:0`. A content-addressed blob in the
 * workspace's own media store is the right owner, and it is the same URL for
 * everyone because it is derived from the bytes.
 *
 * ## Why the upload happens here and not in the browser
 *
 * The relay's media store authenticates with a **signed** kind:24242 event, and
 * the signing key is custodied. A browser upload would mean either handing the
 * browser a secret key — the thing this whole service exists to avoid — or
 * minting a Blossom token through `/sign`, which is exactly the "rubber stamp"
 * `/sign` was constrained to refuse. So the bytes come here and this service
 * signs for its own user, the same internal path `publishProfile` takes.
 *
 * ## Why the *read* happens here too (SHA-22)
 *
 * The same argument, arrived at from the other end. Buzz used to serve
 * `/media/*` unauthenticated behind `BUZZ_REQUIRE_MEDIA_GET_AUTH`; upstream
 * removed that path and made both spellings of the variable inert, so every
 * read now needs a signed kind:24242 `t=get` event in an `Authorization`
 * header. An `<img>` sends no headers and Buzz accepts the credential nowhere
 * else — no query parameter, no cookie — so *no browser* could display an
 * avatar, in any app, however the workspace was configured. Every uploaded
 * picture fell back to initials, and Estiva ID's own profile page showed a
 * broken image for a photo it had just stored.
 *
 * Handing the browser a credential is the thing this service exists to avoid,
 * so the bytes come back through here instead: {@link readAvatar} signs as the
 * relay operator and streams the blob. `picture` is published as this service's
 * URL rather than the relay's — see {@link avatarDisplayUrl}, which keeps the
 * hash in the path so the relay URL is still derivable from it.
 *
 * **This is not a general media proxy**, and the difference is load-bearing.
 * It serves a hash only while some identity's `picture` still refers to it, so
 * it cannot be used to fish for blobs that were never avatars. Buzz's own
 * feedback-attachment route is built the same way and for the same reason:
 * "unknown feedback, unreferenced hashes ... all collapse to `404`".
 */
import { queryOne } from '../db/pool.js'
import {
  type BlobPath,
  type FetchBlobResult,
  fetchBlob,
  parseBlobPath,
  uploadBlob,
} from '../nostr/blossom.js'
import { recordAudit } from './audit.js'
import { AVATAR_PATH, avatarDisplayUrl } from './avatar-url.js'
import { withUserSecretKey } from './keys.js'
import { NoOperatorIdentity, withOperatorSecretKey } from './operator-key.js'
import { publishProfile, saveProfile } from './profile.js'

/**
 * What a profile picture may be.
 *
 * Deliberately narrow. SVG is absent because it is a document that can carry
 * script, and an avatar renders in every app in the suite — a format that
 * executes is not a picture. Buzz sniffs the real type on its side too, so this
 * is the near gate rather than the only one.
 */
const ALLOWED_TYPES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif'])

/**
 * Five megabytes.
 *
 * An avatar is displayed at a few dozen pixels. This is not a storage limit so
 * much as the point past which someone is uploading the wrong file, and finding
 * that out before spending the bandwidth is cheap.
 */
export const MAX_AVATAR_BYTES = 5 * 1024 * 1024

export { AVATAR_PATH, avatarDisplayUrl }

export class AvatarRejected extends Error {
  constructor(
    readonly reason: 'type_not_allowed' | 'too_large' | 'empty',
    message: string,
  ) {
    super(message)
    this.name = 'AvatarRejected'
  }
}

export interface AvatarOutcome {
  /** The content-addressed URL now stored as `picture`. */
  url: string
  sha256: string
  size: number
  /** Whether the `kind:0` carrying it reached the relay. */
  published: boolean
  eventId?: string | undefined
  publishError?: string | undefined
}

/**
 * Upload an avatar, store its URL, and republish the profile.
 *
 * The order matters and is the same one `PUT /me/profile` uses: the upload has
 * to succeed before anything is written, because a `picture` pointing at a blob
 * that was never stored is worse than no change at all. After that, saving and
 * publishing are separate outcomes — Postgres is the record and the relay is a
 * projection of it, so a relay that takes the blob but refuses the event leaves
 * the avatar set and `published: false`, not a rolled-back edit.
 */
export async function setAvatar(
  userId: string,
  bytes: Uint8Array,
  contentType: string,
  options: { requestId?: string } = {},
): Promise<AvatarOutcome> {
  const type = contentType.split(';')[0]?.trim().toLowerCase() ?? ''

  if (bytes.byteLength === 0) throw new AvatarRejected('empty', 'That file is empty')
  if (!ALLOWED_TYPES.has(type)) {
    throw new AvatarRejected(
      'type_not_allowed',
      'A profile picture must be a PNG, JPEG, WebP or GIF',
    )
  }
  if (bytes.byteLength > MAX_AVATAR_BYTES) {
    throw new AvatarRejected('too_large', 'A profile picture must be 5 MB or smaller')
  }

  const upload = await withUserSecretKey(userId, (secretKey) => uploadBlob(bytes, type, secretKey))

  if (!upload.ok) {
    await recordAudit({
      actorType: 'user',
      actorUserId: userId,
      action: 'avatar.upload',
      outcome: upload.reason === 'not_admitted' ? 'refused' : 'error',
      // Never the bytes, and never the URL of something that was not stored.
      //
      // `message` is the media store's own words, and it is here because
      // without it this record said `422` and nothing else — which took reading
      // Buzz's source to interpret (PEEK-96). A status alone is not enough to
      // diagnose a refusal from the log, which is the log's entire job.
      detail: {
        reason: upload.reason,
        httpStatus: upload.httpStatus,
        message: upload.message,
      },
      ...(options.requestId === undefined ? {} : { requestId: options.requestId }),
    })
    throw upload
  }

  await saveProfile(userId, { picture: upload.blob.url })

  await recordAudit({
    actorType: 'user',
    actorUserId: userId,
    action: 'avatar.upload',
    outcome: 'success',
    detail: { sha256: upload.blob.sha256, size: upload.blob.size, type: upload.blob.type },
    ...(options.requestId === undefined ? {} : { requestId: options.requestId }),
  })

  const outcome = await publishProfile(userId, {
    ...(options.requestId === undefined ? {} : { requestId: options.requestId }),
  })

  return {
    url: upload.blob.url,
    sha256: upload.blob.sha256,
    size: upload.blob.size,
    published: outcome.published,
    eventId: outcome.eventId,
    publishError: outcome.published ? undefined : outcome.reason,
  }
}

export type AvatarRead =
  | {
      ok: true
      body: ReadableStream<Uint8Array> | null
      contentType: string
      contentLength: string | null
    }
  | {
      ok: false
      reason:
        | 'not_an_avatar'
        | 'not_found'
        | 'no_operator'
        | 'not_admitted'
        | 'refused'
        | 'unreachable'
      message: string
    }

/**
 * Whether any identity's picture still refers to these bytes.
 *
 * **Any** identity, not only an active one. A leaver's messages stay attributed
 * to them in both apps, so filtering to `active` would blank the face on every
 * message they ever sent while their name stayed — a different regression, in
 * service of hiding the least sensitive half. Offboarding revokes what it is
 * meant to: the `nip05` attestation, and relay admission.
 *
 * Matched on the hash rather than on a whole URL, deliberately: rows written
 * before this existed hold the relay's URL and rows written after hold this
 * service's, and a check keyed to either shape would quietly stop admitting
 * half of them the first time the other shape appeared. A 64-hex hash contains
 * no `like` metacharacter and is validated before it gets here, so containment
 * is both safe and the most durable question to ask.
 */
async function isReferencedAvatar(sha256: string): Promise<boolean> {
  const row = await queryOne<{ one: number }>(
    "select 1 as one from users where picture like '%' || $1 || '%' limit 1",
    [sha256],
  )
  return row !== undefined
}

/**
 * Stream one stored avatar back, signing the read as the relay operator.
 *
 * Signed as the operator rather than as the viewer because the viewer is an
 * `<img>` on another origin: it carries no session and, under `SameSite`, no
 * cookie either. The narrowing that replaces per-viewer authorisation is
 * {@link isReferencedAvatar} — an unreferenced hash is refused before a token
 * is ever minted, so the operator's membership cannot be borrowed to read
 * anything that is not currently somebody's profile picture.
 */
export async function readAvatar(
  segment: string,
  options: { signal?: AbortSignal } = {},
): Promise<AvatarRead> {
  const path: BlobPath | null = parseBlobPath(segment)
  if (!path) return { ok: false, reason: 'not_an_avatar', message: 'Not a blob path' }

  if (!(await isReferencedAvatar(path.sha256))) {
    // Deliberately the same answer as a hash the relay does not hold: whether
    // these particular bytes exist is not something an unauthenticated caller
    // should be able to probe for.
    return { ok: false, reason: 'not_an_avatar', message: 'No profile picture with that hash' }
  }

  /*
    A deployment with no `RELAY_OPERATOR_USER_ID` cannot sign a read at all.
    Caught rather than thrown so it does not surface as "unhandled error" on
    every avatar in the workspace — the log line that says which of these it is
    is the whole difference between a minute and an afternoon.
  */
  let result: FetchBlobResult
  try {
    result = await withOperatorSecretKey((secretKey) => fetchBlob(path, secretKey, options))
  } catch (error) {
    if (error instanceof NoOperatorIdentity) {
      return { ok: false, reason: 'no_operator', message: error.message }
    }
    throw error
  }

  if (result.ok) {
    return {
      ok: true,
      body: result.body,
      contentType: result.contentType,
      contentLength: result.contentLength,
    }
  }
  return { ok: false, reason: result.reason, message: result.message }
}
