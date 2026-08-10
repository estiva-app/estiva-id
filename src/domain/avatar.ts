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
 */
import { uploadBlob } from '../nostr/blossom.js'
import { recordAudit } from './audit.js'
import { withUserSecretKey } from './keys.js'
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
      detail: { reason: upload.reason, httpStatus: upload.httpStatus },
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
