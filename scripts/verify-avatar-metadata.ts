/// <reference lib="dom" />
/**
 * Does `prepareAvatar` really produce bytes the relay will accept? (PEEK-96)
 *
 *   pnpm exec tsx scripts/verify-avatar-metadata.ts
 *
 * Kept in the repo for the same reason `scripts/probe-blossom.ts` is: the rule
 * being satisfied lives in Buzz's source rather than in a spec, this is cheap to
 * re-run, and if either side of it changes this is what notices.
 *
 * ## Why a real browser, and not a unit test
 *
 * `prepareAvatar` is `createImageBitmap` and `<canvas>`, neither of which jsdom
 * implements — so there is nothing to assert against in Vitest, and `web/` has
 * no test files at all. Mocking the canvas would test the mock: the interesting
 * behaviour *is* the encoder's.
 *
 * That is not a technicality. Re-encoding through a canvas was assumed to be
 * sufficient to strip metadata, and it is not: **Chromium's
 * `toBlob('image/jpeg')` writes an APP2 ICC colour profile into its output**,
 * and `0xe2` is inside the `0xe1`–`0xed` range Buzz refuses. So the first
 * version stripped the phone's EXIF and the encoder immediately put back a
 * marker of the same class, leaving uploads failing exactly as before. Only a
 * real encoder shows that, which is why this script exists rather than a fixture.
 *
 * ## What it proves, and what it does not
 *
 * It proves the bytes satisfy the rules read out of
 * `crates/buzz-media/src/validation.rs` — no forbidden JPEG marker, no PNG
 * textual chunk — and that EXIF orientation is applied to the pixels *before*
 * being discarded, without which stripping metadata would silently tip portrait
 * photos onto their side.
 *
 * **It does not prove Buzz accepts them.** Nothing is uploaded and no key is
 * used; that needs a `PUT /me/avatar` against a live relay by an admitted
 * identity. This is the near gate, the same way `probe-blossom.ts` proves the
 * auth event without proving a stored blob.
 *
 * Needs a browser in the Playwright cache. `playwright-core` carries the
 * downloader but not the `playwright` CLI wrapper, so it is invoked directly:
 *
 *   node node_modules/playwright-core/cli.js install chromium-headless-shell
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright-core'
import { transformWithOxc } from 'vite'

/**
 * Refused by `validate_image_metadata_free()`: `0xe1`–`0xed` (EXIF, XMP, ICC),
 * `0xef`, and the `0xfe` comment. `0xe0` (canonical JFIF) and `0xee` (a 12-byte
 * Adobe block) are the two allowed, so they are absent here.
 */
const FORBIDDEN_MARKERS = new Set([...Array.from({ length: 13 }, (_, i) => 0xe1 + i), 0xef, 0xfe])
const PNG_TEXT_CHUNKS = new Set(['tEXt', 'zTXt', 'iTXt'])

const MODULE = fileURLToPath(new URL('../web/src/image.ts', import.meta.url))

/**
 * A minimal EXIF APP1 carrying one Orientation tag.
 *
 * Hand-built rather than taken from a fixture photo so the expected result is
 * derivable: orientation 6 means "rotate 90° clockwise to display", so a stored
 * landscape must come back portrait.
 */
function exifApp1(orientation: number): Buffer {
  const tiff = Buffer.concat([
    Buffer.from('II', 'ascii'), // little-endian
    Buffer.from([0x2a, 0x00]),
    Buffer.from([0x08, 0x00, 0x00, 0x00]), // IFD0 at offset 8
    Buffer.from([0x01, 0x00]), // one entry
    // tag 0x0112 (Orientation), type 3 (SHORT), count 1, then the value
    Buffer.from([0x12, 0x01, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, orientation, 0x00, 0x00, 0x00]),
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // no next IFD
  ])
  const payload = Buffer.concat([Buffer.from('Exif\0\0', 'binary'), tiff])
  return withLength(0xe1, payload)
}

/** A JPEG comment — `0xfe`, the other marker a phone editor leaves behind. */
const comment = (text: string) => withLength(0xfe, Buffer.from(text, 'ascii'))

function withLength(marker: number, payload: Buffer): Buffer {
  const length = payload.length + 2
  return Buffer.concat([
    Buffer.from([0xff, marker]),
    Buffer.from([length >> 8, length & 0xff]),
    payload,
  ])
}

/** Segment markers from SOI up to the scan, where parsing stops meaning anything. */
function jpegMarkers(buf: Buffer): number[] {
  const seen: number[] = []
  let i = 2
  while (i < buf.length - 1) {
    if (buf[i] !== 0xff) break
    const marker = buf[i + 1]
    if (marker === undefined) break
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      i += 2
      continue
    }
    // Start of scan: entropy-coded bytes follow and `0xff` no longer means marker.
    if (marker === 0xda) break
    seen.push(marker)
    i += 2 + buf.readUInt16BE(i + 2)
  }
  return seen
}

function pngChunks(buf: Buffer): string[] {
  const seen: string[] = []
  let i = 8 // past the signature
  while (i + 8 <= buf.length) {
    const length = buf.readUInt32BE(i)
    const type = buf.toString('ascii', i + 4, i + 8)
    seen.push(type)
    if (type === 'IEND') break
    i += 12 + length
  }
  return seen
}

const hex = (markers: number[]) => markers.map((m) => `0x${m.toString(16)}`).join(' ') || '(none)'

/** Same convention as the other scripts here: stdout, not a logger. */
const out = (line = '') => process.stdout.write(`${line}\n`)

interface Prepared {
  type: string
  width: number
  height: number
  base64: string
}

async function main(): Promise<number> {
  // `transformWithOxc` only strips types — it does not bundle, so `export`
  // survives and would be a syntax error in the classic script the page runs.
  // Removing it and naming the global here keeps this independent of whichever
  // transformer Vite ships next.
  const stripped = await transformWithOxc(readFileSync(MODULE, 'utf8'), MODULE)
  const script = `${stripped.code.replace(/^export /gm, '')}\nglobalThis.ImageMod = { prepareAvatar }`

  const browser = await chromium.launch()
  const page = await browser.newPage()
  await page.goto('about:blank')
  await page.addScriptTag({ content: script })

  /** Encode a solid test image in the page, so it is a real browser-made file. */
  const source = (width: number, height: number, mime: string) =>
    page.evaluate(
      async ({ width, height, mime }) => {
        const canvas = document.createElement('canvas')
        canvas.width = width
        canvas.height = height
        const context = canvas.getContext('2d')
        if (!context) throw new Error('no 2d context')
        context.fillStyle = '#3355ff'
        context.fillRect(0, 0, width, height)
        // An off-centre mark, so an orientation change is visible in the pixels
        // and not only in the reported dimensions.
        context.fillStyle = '#ffcc00'
        context.fillRect(0, 0, width / 4, height / 4)
        const blob = await new Promise<Blob | null>((r) => canvas.toBlob(r, mime, 0.92))
        if (!blob) throw new Error('toBlob returned nothing')
        const bytes = new Uint8Array(await blob.arrayBuffer())
        let binary = ''
        for (const byte of bytes) binary += String.fromCharCode(byte)
        return btoa(binary)
      },
      { width, height, mime },
    )

  const prepare = (base64: string, mime: string): Promise<Prepared> =>
    page.evaluate(
      async ({ base64, mime }) => {
        const binary = atob(base64)
        const bytes = new Uint8Array(binary.length)
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)

        const mod = (
          globalThis as unknown as { ImageMod: { prepareAvatar(f: File): Promise<Blob> } }
        ).ImageMod
        const blob = await mod.prepareAvatar(new File([bytes], 'picture', { type: mime }))

        const bitmap = await createImageBitmap(blob)
        const out = new Uint8Array(await blob.arrayBuffer())
        let encoded = ''
        for (const byte of out) encoded += String.fromCharCode(byte)
        return {
          type: blob.type,
          width: bitmap.width,
          height: bitmap.height,
          base64: btoa(encoded),
        }
      },
      { base64, mime },
    )

  const checks: Array<[string, boolean, string]> = []

  // --- A photo off a phone: EXIF orientation, plus a comment carrying GPS ----
  const baseJpeg = Buffer.from(await source(800, 400, 'image/jpeg'), 'base64')
  const photo = Buffer.concat([
    baseJpeg.subarray(0, 2), // SOI
    exifApp1(6),
    comment('GPS 50.0755N 14.4378E'),
    baseJpeg.subarray(2),
  ])

  out(`JPEG in  : ${hex(jpegMarkers(photo))}  (${photo.length} B, 800x400, orientation 6)`)
  const jpeg = await prepare(photo.toString('base64'), 'image/jpeg')
  const jpegOut = Buffer.from(jpeg.base64, 'base64')
  const survivors = jpegMarkers(jpegOut).filter((m) => FORBIDDEN_MARKERS.has(m))
  out(
    `JPEG out : ${hex(jpegMarkers(jpegOut))}  (${jpegOut.length} B, ${jpeg.width}x${jpeg.height}, ${jpeg.type})`,
  )

  checks.push(
    ['JPEG: no forbidden marker survives', survivors.length === 0, hex(survivors)],
    [
      'JPEG: orientation applied to the pixels before EXIF was discarded',
      jpeg.width === 256 && jpeg.height === 512,
      `${jpeg.width}x${jpeg.height}, wanted 256x512`,
    ],
    ['JPEG: long edge capped', Math.max(jpeg.width, jpeg.height) === 512, ''],
    ['JPEG: stays JPEG', jpeg.type === 'image/jpeg', jpeg.type],
    ['JPEG: smaller than the original', jpegOut.length < photo.length, ''],
  )

  // --- A PNG, which has to keep the format that can carry transparency ------
  const basePng = Buffer.from(await source(300, 900, 'image/png'), 'base64')
  out(`\nPNG  in  : ${pngChunks(basePng).join(' ')}  (${basePng.length} B, 300x900)`)
  const png = await prepare(basePng.toString('base64'), 'image/png')
  const pngOut = Buffer.from(png.base64, 'base64')
  const textChunks = pngChunks(pngOut).filter((c) => PNG_TEXT_CHUNKS.has(c))
  out(
    `PNG  out : ${pngChunks(pngOut).join(' ')}  (${pngOut.length} B, ${png.width}x${png.height}, ${png.type})`,
  )

  checks.push(
    ['PNG: no textual chunk', textChunks.length === 0, textChunks.join(' ')],
    ['PNG: stays PNG, so transparency survives', png.type === 'image/png', png.type],
    [
      'PNG: long edge capped',
      Math.max(png.width, png.height) === 512,
      `${png.width}x${png.height}`,
    ],
  )

  out()
  let failures = 0
  for (const [name, passed, detail] of checks) {
    if (!passed) failures++
    out(`${passed ? 'PASS' : 'FAIL'}  ${name}${passed || !detail ? '' : `  → ${detail}`}`)
  }

  await browser.close()
  return failures === 0 ? 0 : 1
}

process.exit(await main())
