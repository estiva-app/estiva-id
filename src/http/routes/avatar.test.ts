/**
 * SHA-22: serving a stored picture to a browser.
 *
 * The behaviour under test is the one the ticket is about — an `<img>` with no
 * headers and no cookie gets the bytes — so the request is made without either,
 * deliberately, and the relay is stubbed so its half of the contract is stated
 * here in one place: it wants `Authorization: Nostr <base64 kind:24242 t=get>`.
 *
 * What this cannot check is the same thing `http/cors.ts` warns about: nothing
 * in process enforces the browser's rules. That an `<img>` on `peek.estiva.app`
 * actually paints is verified against the deployment, not here.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const RELAY = 'https://relay.test'
const SHA = 'a'.repeat(64)
const OTHER_SHA = 'b'.repeat(64)
const BYTES = Uint8Array.from([0x89, 0x50, 0x4e, 0x47])

/** Point the config at an operator identity for the duration of one test. */
async function withOperator<T>(userId: string, run: () => Promise<T>): Promise<T> {
  const { resetConfigForTests } = await import('../../config.js')
  process.env.RELAY_OPERATOR_USER_ID = userId
  resetConfigForTests()
  try {
    return await run()
  } finally {
    process.env.RELAY_OPERATOR_USER_ID = ''
    resetConfigForTests()
  }
}

/** Stand in for the media store, capturing what it was actually asked. */
function relayServing(status: number, body?: BodyInit) {
  const calls: { url: string; authorization: string | null }[] = []
  vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers)
    calls.push({ url: String(input), authorization: headers.get('authorization') })
    return new Response(status === 200 ? (body ?? BYTES) : 'nope', {
      status,
      headers: status === 200 ? { 'content-type': 'image/png', 'content-length': '4' } : {},
    })
  })
  return calls
}

/** An active identity whose picture is these bytes on the relay. */
async function personWithPicture(sha: string) {
  const user = await createUserWithKey({ email: `${sha.slice(0, 8)}@test`, displayName: 'Someone' })
  await query('update users set picture = $2 where id = $1', [user.id, `${RELAY}/media/${sha}.jpg`])
  return user
}

beforeAll(async () => {
  process.env.RELAY_BRIDGE_URL = RELAY
  process.env.COMMUNITY_HOST = 'estiva.test'
  const { resetConfigForTests } = await import('../../config.js')
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

describe('GET /avatar/:file', () => {
  it('returns the bytes to a caller with no credential of its own', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      relayServing(200)
      // No Authorization, no Cookie — exactly what an <img> sends.
      const res = await createApp().request(`/avatar/${SHA}.jpg`)

      expect(res.status).toBe(200)
      expect(res.headers.get('content-type')).toBe('image/png')
      expect(new Uint8Array(await res.arrayBuffer())).toEqual(BYTES)
    })
  })

  it('signs the relay read itself, blob-scoped', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      const calls = relayServing(200)
      await createApp().request(`/avatar/${SHA}.jpg`)

      expect(calls).toHaveLength(1)
      expect(calls[0]?.url).toBe(`${RELAY}/media/${SHA}.jpg`)

      const header = calls[0]?.authorization ?? ''
      expect(header.startsWith('Nostr ')).toBe(true)
      const event = JSON.parse(Buffer.from(header.slice(6), 'base64').toString('utf8'))
      expect(event.kind).toBe(24242)
      expect(event.tags).toContainEqual(['t', 'get'])
      expect(event.tags).toContainEqual(['x', SHA])
    })
  })

  it('lets the bytes be cached, because the URL names them', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      relayServing(200)
      const res = await createApp().request(`/avatar/${SHA}.jpg`)

      expect(res.headers.get('cache-control')).toContain('public')
      expect(res.headers.get('cache-control')).toContain('immutable')
      expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    })
  })

  it('refuses a hash nobody has as their picture, without asking the relay', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      const calls = relayServing(200)
      const res = await createApp().request(`/avatar/${OTHER_SHA}.jpg`)

      expect(res.status).toBe(404)
      // The narrowing is the security argument: an unreferenced hash must not
      // borrow the operator's membership, so no token is minted at all.
      expect(calls).toHaveLength(0)
    })
  })

  it('answers a hash the relay does not hold the same way it answers an unreferenced one', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      relayServing(404)
      const present = await createApp().request(`/avatar/${SHA}.jpg`)
      const absent = await createApp().request(`/avatar/${OTHER_SHA}.jpg`)

      expect(present.status).toBe(404)
      expect(absent.status).toBe(404)
    })
  })

  it('does not report an unadmitted operator as a missing picture', async () => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      relayServing(403)
      const res = await createApp().request(`/avatar/${SHA}.jpg`)

      // 403 from the relay means nobody admitted this deployment's operator
      // key — an operator bootstrap step, not a picture that is not there.
      expect(res.status).toBe(500)
      expect((await res.json()).error.detail.reason).toBe('not_admitted')
    })
  })

  it('does not report an unconfigured operator as a missing picture', async () => {
    await personWithPicture(SHA)

    // No withOperator: RELAY_OPERATOR_USER_ID is unset, which is a deployment
    // that cannot sign a read at all. It must not read as "no such picture",
    // and it must not surface as an unhandled error on every avatar.
    const calls = relayServing(200)
    const res = await createApp().request(`/avatar/${SHA}.jpg`)

    expect(res.status).toBe(500)
    expect((await res.json()).error.detail.reason).toBe('no_operator')
    expect(calls).toHaveLength(0)
  })

  it.each([
    ['traversal', '..%2F..%2Fevents'],
    ['a short hash', `${'a'.repeat(63)}.jpg`],
    ['no extension', SHA],
  ])('refuses %s', async (_label, segment) => {
    const operator = await createUserWithKey({ displayName: 'Operator', kind: 'role' })
    await personWithPicture(SHA)

    await withOperator(operator.id, async () => {
      const calls = relayServing(200)
      expect((await createApp().request(`/avatar/${segment}`)).status).toBe(404)
      expect(calls).toHaveLength(0)
    })
  })
})
