/**
 * SHA-22: the read half of the media store's Blossom auth.
 *
 * Kept out of `domain/avatar.test.ts` because none of it needs a database, and
 * the rules being checked are Buzz's rather than ours — every assertion here
 * mirrors a line in `crates/buzz-media/src/auth.rs`, so a failure means one
 * side moved.
 *
 * As with the upload path, only a live relay can say whether a token is
 * *acceptable*; what is settled here is that we mint the shape its verifier
 * looks for, and that a hostile path segment never reaches a URL.
 */
import { beforeAll, describe, expect, it } from 'vitest'
import { authorizationHeader, buildAuthEvent, parseBlobPath } from './blossom.js'
import { verifyEvent } from './keys.js'

const HOST = 'estiva.test'
const SHA = 'a'.repeat(64)
const secretKey = Buffer.alloc(32, 7)

beforeAll(async () => {
  process.env.COMMUNITY_HOST = HOST
  process.env.RELAY_BRIDGE_URL = 'https://relay.test'
  const { resetConfigForTests } = await import('../config.js')
  resetConfigForTests()
})

const tagValue = (event: { tags: string[][] }, name: string) =>
  event.tags.find((tag) => tag[0] === name)?.[1]

describe('the get token', () => {
  it('is a signed kind:24242 carrying t=get', () => {
    const event = buildAuthEvent('get', { secretKey, sha256Hex: SHA, host: HOST })

    expect(event.kind).toBe(24242)
    expect(tagValue(event, 't')).toBe('get')
    expect(verifyEvent(event)).toBe(true)
  })

  it('is scoped to one blob as well as to this host', () => {
    // Buzz accepts either. A `server`-only token would grant reads for every
    // blob on the host until it expires — sending both keeps it to one.
    const event = buildAuthEvent('get', { secretKey, sha256Hex: SHA, host: HOST })

    expect(tagValue(event, 'x')).toBe(SHA)
    expect(tagValue(event, 'server')).toBe(HOST)
  })

  it('expires, and in the future', () => {
    const nowMs = 1_700_000_000_000
    const event = buildAuthEvent('get', { secretKey, sha256Hex: SHA, host: HOST, nowMs })

    expect(Number(tagValue(event, 'expiration'))).toBeGreaterThan(nowMs / 1000)
  })

  it('says something, because an empty content is refused', () => {
    expect(buildAuthEvent('get', { secretKey, sha256Hex: SHA, host: HOST }).content).not.toBe('')
  })

  it('differs from an upload token only in the verb it claims', () => {
    const nowMs = 1_700_000_000_000
    const get = buildAuthEvent('get', { secretKey, sha256Hex: SHA, host: HOST, nowMs })
    const upload = buildAuthEvent('upload', { secretKey, sha256Hex: SHA, host: HOST, nowMs })

    expect(tagValue(get, 't')).toBe('get')
    expect(tagValue(upload, 't')).toBe('upload')
    expect(get.id).not.toBe(upload.id)
  })

  it('rides in the header as base64 of the event JSON', () => {
    const header = authorizationHeader('get', { secretKey, sha256Hex: SHA, host: HOST })

    expect(header.startsWith('Nostr ')).toBe(true)
    const decoded = JSON.parse(
      Buffer.from(header.slice('Nostr '.length), 'base64').toString('utf8'),
    )
    expect(decoded.kind).toBe(24242)
    expect(verifyEvent(decoded)).toBe(true)
  })
})

describe('a blob path', () => {
  it('is a hash and an extension', () => {
    expect(parseBlobPath(`${SHA}.jpg`)).toEqual({ sha256: SHA, ext: 'jpg' })
  })

  it('may be a thumbnail, which the relay mints itself', () => {
    expect(parseBlobPath(`${SHA}.thumb.jpg`)).toEqual({ sha256: SHA, ext: 'thumb.jpg' })
  })

  it.each([
    ['traversal', '../../etc/passwd'],
    ['traversal inside a plausible name', `${SHA}.../../x`],
    ['an absolute path', `/${SHA}.jpg`],
    ['another origin', `https://evil.test/${SHA}.jpg`],
    ['a short hash', `${'a'.repeat(63)}.jpg`],
    ['a long hash', `${'a'.repeat(65)}.jpg`],
    ['upper-case hex, which Buzz does not mint', `${'A'.repeat(64)}.jpg`],
    ['no extension', SHA],
    ['an empty extension', `${SHA}.`],
    ['an overlong extension', `${SHA}.abcdefghi`],
    ['a query string smuggled in', `${SHA}.jpg?x=1`],
    ['nothing at all', ''],
  ])('is not %s', (_label, segment) => {
    expect(parseBlobPath(segment)).toBeNull()
  })
})
