/**
 * Re-encoding a chosen picture before it is uploaded (PEEK-96).
 *
 * ## Why this exists
 *
 * Buzz's media store runs `validate_image_metadata_free()` on every upload and
 * refuses anything carrying metadata — for JPEG that is markers `0xe1`–`0xed`
 * (EXIF, XMP, ICC), `0xef` and `0xfe`; for PNG, any textual chunk. **Every photo
 * off a phone carries EXIF**, so before this, choosing a real picture failed with
 * a `422` and a message that invited the person to try a different file, when the
 * answer was "any file, until it is stripped".
 *
 * That refusal is deliberate Buzz policy, not a bug to route around: an avatar is
 * republished to everyone, and EXIF carries GPS and camera data. Which is the
 * second reason to strip here — without it, anybody uploading a phone photo would
 * be publishing their coordinates to a shared relay, permanently. That would be
 * true even if the relay accepted it.
 *
 * ## How
 *
 * Drawing to a `<canvas>` and re-encoding keeps only pixels: every marker and
 * chunk the relay objects to is discarded by construction, rather than by an
 * allowlist we would have to keep in step with Buzz's.
 *
 * `createImageBitmap` is given `imageOrientation: 'from-image'` explicitly. EXIF
 * is about to be discarded, so an orientation tag that was rotating the picture
 * has to be *applied* to the pixels first — otherwise stripping metadata would
 * silently turn portrait photos on their side.
 */

/**
 * The long edge, in pixels.
 *
 * An avatar renders at a few dozen pixels; 512 leaves room for a retina detail
 * view and still turns a 12-megapixel original into a few hundred kilobytes.
 * There is no reason to ship the original to every app in the suite.
 */
export const MAX_AVATAR_DIMENSION = 512

/** Matches `MAX_AVATAR_BYTES` in `src/domain/avatar.ts`. */
const MAX_AVATAR_BYTES = 5 * 1024 * 1024

const JPEG_QUALITY = 0.9

export class ImageUnreadable extends Error {
  constructor() {
    super('That file could not be read as a picture')
    this.name = 'ImageUnreadable'
  }
}

/**
 * Strip metadata and downscale, returning bytes safe to upload.
 *
 * JPEG stays JPEG. Everything else becomes PNG, because PNG is the output that
 * keeps transparency and PNG, WebP and GIF can all carry it — re-encoding a
 * logo with a transparent background to JPEG would paint it black.
 *
 * **An animated GIF becomes a still**, since a canvas holds one frame. Accepted:
 * the alternative is shipping an animation to every app in the suite, and today
 * such a file is refused outright, so this is strictly more than worked before.
 */
export async function prepareAvatar(file: File): Promise<Blob> {
  let bitmap: ImageBitmap
  try {
    bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' })
  } catch {
    throw new ImageUnreadable()
  }

  try {
    const scale = Math.min(1, MAX_AVATAR_DIMENSION / Math.max(bitmap.width, bitmap.height))
    const width = Math.max(1, Math.round(bitmap.width * scale))
    const height = Math.max(1, Math.round(bitmap.height * scale))

    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height

    const context = canvas.getContext('2d')
    if (!context) throw new ImageUnreadable()
    context.drawImage(bitmap, 0, 0, width, height)

    const type = file.type === 'image/jpeg' ? 'image/jpeg' : 'image/png'
    const encoded = await clean(await toBlob(canvas, type))

    // A downscaled PNG of a photograph can still be large. Falling back to JPEG
    // beats telling somebody their picture is too big immediately after we
    // shrank it — which would be the one message they cannot act on.
    if (encoded.size > MAX_AVATAR_BYTES && type === 'image/png') {
      return await clean(await toBlob(canvas, 'image/jpeg'))
    }
    return encoded
  } finally {
    bitmap.close()
  }
}

/**
 * JPEG markers Buzz refuses: EXIF, XMP, ICC and the rest of `0xe1`–`0xed`, plus
 * `0xef` and the `0xfe` comment. `0xe0` (canonical JFIF) and `0xee` (a 12-byte
 * Adobe block) are the two it allows, so they are absent here.
 */
const FORBIDDEN_JPEG_MARKERS = new Set([
  0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xef, 0xfe,
])

/**
 * Drop metadata segments the canvas encoder *added*.
 *
 * Re-encoding is not sufficient on its own, which is only visible in a browser:
 * Chromium's `toBlob('image/jpeg')` writes an **APP2 ICC colour profile** into
 * its output, and `0xe2` is inside the range Buzz refuses. So a picture that
 * arrived clean would still have been rejected — the encoder puts back a marker
 * of the same class as the one we just removed.
 *
 * Filtering the encoded bytes makes the result conform by construction rather
 * than by trusting what a particular browser's encoder chooses to emit, which
 * is not a thing we control or get told about when it changes.
 */
async function clean(blob: Blob): Promise<Blob> {
  if (blob.type !== 'image/jpeg') return blob

  const bytes = new Uint8Array(await blob.arrayBuffer())
  if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return blob

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const keep: Uint8Array<ArrayBuffer>[] = [bytes.subarray(0, 2)]

  let i = 2
  while (i < bytes.length - 1) {
    if (bytes[i] !== 0xff) break
    const marker = bytes[i + 1]
    if (marker === undefined) break

    // Standalone markers carry no length.
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      keep.push(bytes.subarray(i, i + 2))
      i += 2
      continue
    }
    // Start of scan: entropy-coded data follows, where `0xff` bytes are stuffed
    // rather than markers. Nothing past here can be parsed this way, and
    // nothing past here is metadata.
    if (marker === 0xda) {
      keep.push(bytes.subarray(i))
      i = bytes.length
      break
    }

    const end = i + 2 + view.getUint16(i + 2)
    if (!FORBIDDEN_JPEG_MARKERS.has(marker)) keep.push(bytes.subarray(i, end))
    i = end
  }

  return new Blob(keep, { type: 'image/jpeg' })
}

function toBlob(canvas: HTMLCanvasElement, type: string): Promise<Blob> {
  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => (blob ? resolve(blob) : reject(new ImageUnreadable())),
      type,
      type === 'image/jpeg' ? JPEG_QUALITY : undefined,
    )
  })
}
