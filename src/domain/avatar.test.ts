/**
 * PEEK-32: avatars on the relay's media store.
 *
 * The BUD-11 auth event itself is checked against a *live* relay by
 * `scripts/probe-blossom.ts`, because only Buzz can say whether it is
 * acceptable and a mock would only confirm the mock. What is checked here is
 * everything around it: what we refuse before uploading, what we store
 * afterwards, and that a relay refusal cannot leave a `picture` pointing at a
 * blob nobody kept.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool, queryOne } from '../db/pool.js'
import { buildUploadAuthEvent } from '../nostr/blossom.js'
import { verifyEvent } from '../nostr/keys.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { AvatarRejected, MAX_AVATAR_BYTES, setAvatar } from './avatar.js'
import { getProfile } from './profile.js'
import { createUserWithKey } from './users.js'

/** A real 1x1 PNG. */
const PNG = Uint8Array.from(
  Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
    'base64',
  ),
)

const HOST = 'estiva.test'

beforeAll(async () => {
  process.env.COMMUNITY_HOST = HOST
  process.env.RELAY_BRIDGE_URL = 'https://relay.test'
  const { resetConfigForTests } = await import('../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

afterAll(async () => {
  await closePool()
})

/** Stand in for the media store, capturing what we actually sent it. */
function stubRelay(handler: (request: Request) => Response | Promise<Response>) {
  const seen: Request[] = []
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(String(input), init)
    seen.push(request.clone())
    return handler(request)
  })
  return seen
}

const descriptor = (sha256: string) =>
  new Response(
    JSON.stringify({
      url: `https://${HOST}/media/${sha256}.png`,
      sha256,
      size: PNG.byteLength,
      type: 'image/png',
      uploaded: Math.floor(Date.now() / 1000),
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  )

describe('the authorization event', () => {
  it('carries everything Buzz requires, and is signed by the user', () => {
    const secretKey = Buffer.alloc(32, 7)
    const event = buildUploadAuthEvent({ secretKey, sha256Hex: 'a'.repeat(64), host: HOST })

    expect(event.kind).toBe(24242)
    expect(verifyEvent(event)).toBe(true)

    const tag = (name: string) => event.tags.find(([key]) => key === name)?.[1]
    expect(tag('t')).toBe('upload')
    expect(tag('x')).toBe('a'.repeat(64))
    expect(tag('server')).toBe(HOST)

    // Required, and in the future — a missing or past expiration is refused.
    expect(Number(tag('expiration'))).toBeGreaterThan(Math.floor(Date.now() / 1000))

    // Buzz rejects an empty content field as InvalidAuthEvent, which is not
    // something BUD-11 makes obvious.
    expect(event.content.trim()).not.toBe('')
  })

  it('binds the token to the exact bytes, so it cannot be reused for another file', () => {
    const secretKey = Buffer.alloc(32, 7)
    const one = buildUploadAuthEvent({ secretKey, sha256Hex: 'a'.repeat(64), host: HOST })
    const two = buildUploadAuthEvent({ secretKey, sha256Hex: 'b'.repeat(64), host: HOST })
    expect(one.tags.find(([k]) => k === 'x')?.[1]).not.toBe(two.tags.find(([k]) => k === 'x')?.[1])
  })
})

describe('what is refused before anything is uploaded', () => {
  it('refuses a type that is not an image', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    const seen = stubRelay(() => new Response('{}', { status: 200 }))

    await expect(setAvatar(user.id, PNG, 'application/pdf')).rejects.toThrow(AvatarRejected)
    expect(seen).toHaveLength(0)
  })

  /**
   * SVG is a document that can carry script, and an avatar renders in every app
   * in the suite. A format that executes is not a picture.
   */
  it('refuses SVG specifically', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(() => new Response('{}', { status: 200 }))
    await expect(setAvatar(user.id, PNG, 'image/svg+xml')).rejects.toMatchObject({
      reason: 'type_not_allowed',
    })
  })

  it('refuses an empty file and one over the limit', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(() => new Response('{}', { status: 200 }))

    await expect(setAvatar(user.id, new Uint8Array(0), 'image/png')).rejects.toMatchObject({
      reason: 'empty',
    })
    await expect(
      setAvatar(user.id, new Uint8Array(MAX_AVATAR_BYTES + 1), 'image/png'),
    ).rejects.toMatchObject({ reason: 'too_large' })
  })

  it('accepts a content type carrying a charset parameter', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(async (request) => descriptor(request.headers.get('x-sha-256') ?? ''))
    await expect(setAvatar(user.id, PNG, 'image/png; charset=binary')).resolves.toBeTruthy()
  })
})

describe('the upload request', () => {
  it('sends the mandatory X-SHA-256 header, matching the x tag and the body', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    const seen = stubRelay(async (request) => descriptor(request.headers.get('x-sha-256') ?? ''))

    await setAvatar(user.id, PNG, 'image/png')

    const request = seen[0]
    expect(request?.url).toBe('https://relay.test/media/upload')
    expect(request?.method).toBe('PUT')

    const claimed = request?.headers.get('x-sha-256')
    expect(claimed).toMatch(/^[0-9a-f]{64}$/)

    // Without this agreement the relay answers HashMismatch before reading the
    // body, and the failure looks like a network problem rather than a bug here.
    const header = request?.headers.get('authorization') ?? ''
    const event = JSON.parse(
      Buffer.from(header.replace('Nostr ', ''), 'base64').toString('utf8'),
    ) as { tags: string[][]; pubkey: string }
    expect(event.tags.find(([k]) => k === 'x')?.[1]).toBe(claimed)
    expect(event.pubkey).toBe(user.pubkey)
  })
})

describe('what happens afterwards', () => {
  it('stores the content-addressed URL and republishes the profile', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(async (request) => {
      if (request.url.endsWith('/media/upload')) {
        return descriptor(request.headers.get('x-sha-256') ?? '')
      }
      return new Response(JSON.stringify({ accepted: true, event_id: 'abc' }), { status: 200 })
    })

    const outcome = await setAvatar(user.id, PNG, 'image/png')

    expect(outcome.url).toContain(`/media/${outcome.sha256}.png`)
    expect(outcome.published).toBe(true)
    await expect(getProfile(user.id)).resolves.toMatchObject({ picture: outcome.url })
  })

  /**
   * Postgres is the record, the relay is a projection. A relay that stores the
   * blob but refuses the event leaves the avatar set and says so, rather than
   * rolling back an upload that already happened.
   */
  it('keeps the avatar when the profile event cannot be published', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(async (request) => {
      if (request.url.endsWith('/media/upload')) {
        return descriptor(request.headers.get('x-sha-256') ?? '')
      }
      return new Response(JSON.stringify({ error: 'relay is down' }), { status: 503 })
    })

    const outcome = await setAvatar(user.id, PNG, 'image/png')
    expect(outcome.published).toBe(false)
    await expect(getProfile(user.id)).resolves.toMatchObject({ picture: outcome.url })
  })

  /**
   * The opposite order, and the one that matters more: if the media store
   * refused, nothing may be written. A `picture` pointing at a blob that was
   * never stored is a broken avatar in every app at once.
   */
  it('writes nothing when the media store refuses', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(async () => new Response(JSON.stringify({ error: 'nope' }), { status: 422 }))

    await expect(setAvatar(user.id, PNG, 'image/png')).rejects.toMatchObject({
      ok: false,
      reason: 'rejected',
    })
    await expect(getProfile(user.id)).resolves.toMatchObject({ picture: null })
  })

  it('reports a closed relay as not_admitted rather than a generic failure', async () => {
    const user = await createUserWithKey({ email: 'ada@example.test' })
    stubRelay(
      async () =>
        new Response(JSON.stringify({ error: 'relay membership required' }), { status: 403 }),
    )

    await expect(setAvatar(user.id, PNG, 'image/png')).rejects.toMatchObject({
      reason: 'not_admitted',
    })

    // Audited as a refusal, not an error: nothing went wrong, somebody just has
    // not been let in yet.
    const audit = await queryOne<{ outcome: string; detail: string }>(
      "select outcome, detail::text as detail from audit_events where action = 'avatar.upload'",
    )
    expect(audit?.outcome).toBe('refused')
    expect(audit?.detail).toContain('not_admitted')
  })
})
