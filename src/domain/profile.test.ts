/**
 * PEEK-31 acceptance, below the HTTP layer.
 *
 * The claim being tested is *"one canonical profile, published once"* — so what
 * matters here is that the handle namespace holds, that clearing means clearing,
 * and that a relay failure does not eat the edit.
 */
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool, query } from '../db/pool.js'
import { createUserWithKey } from '../domain/users.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import {
  HandleTakenError,
  InvalidHandleError,
  getProfile,
  nip05Value,
  publishProfile,
  saveProfile,
} from './profile.js'

const HOST = 'estiva.estiva.app'

/** Captures what would have gone to the relay, and answers as the relay does. */
function stubRelay(response: { status?: number; body: unknown }) {
  const calls: { url: string; body: Record<string, unknown>; authorization: string | undefined }[] =
    []
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init: RequestInit) => {
      calls.push({
        url,
        body: JSON.parse(init.body as string),
        authorization: (init.headers as Record<string, string>).authorization,
      })
      return new Response(JSON.stringify(response.body), { status: response.status ?? 200 })
    }),
  )
  return calls
}

let ada: Awaited<ReturnType<typeof createUserWithKey>>

beforeAll(async () => {
  process.env.COMMUNITY_HOST = HOST
  process.env.RELAY_BRIDGE_URL = 'https://estiva.estiva.app'
  const { resetConfigForTests } = await import('../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  ada = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
})

afterEach(() => {
  vi.unstubAllGlobals()
})

afterAll(async () => {
  await closePool()
})

describe('saveProfile', () => {
  it('stores a handle against the community host, not against the person alone', async () => {
    await saveProfile(ada.id, { handle: 'ada' })

    const rows = await query<{ community_host: string; handle: string }>(
      'select community_host, handle from user_handles where user_id = $1',
      [ada.id],
    )
    expect(rows.rows).toEqual([{ community_host: HOST, handle: 'ada' }])
  })

  it('assembles nip05 from the two halves rather than storing the joined string', async () => {
    const profile = await saveProfile(ada.id, { handle: 'ada' })
    expect(profile.handle).toBe('ada')
    expect(nip05Value(profile)).toBe(`ada@${HOST}`)
  })

  it('lowercases a handle so the relay’s case-insensitive lookup cannot collide', async () => {
    const profile = await saveProfile(ada.id, { handle: 'Ada' })
    expect(profile.handle).toBe('ada')
  })

  // Without the (community_host, handle) constraint the second writer silently
  // wins the name at the relay, which looks like an impersonation rather than
  // a conflict.
  it('refuses a handle another person already holds in the same workspace', async () => {
    const grace = await createUserWithKey({ email: 'grace@example.test' })
    await saveProfile(ada.id, { handle: 'ada' })

    await expect(saveProfile(grace.id, { handle: 'ada' })).rejects.toBeInstanceOf(HandleTakenError)
  })

  it('lets the same person change their own handle', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    const profile = await saveProfile(ada.id, { handle: 'ada-l' })
    expect(profile.handle).toBe('ada-l')

    const rows = await query('select 1 from user_handles where user_id = $1', [ada.id])
    expect(rows.rowCount).toBe(1)
  })

  it('rejects a local part nip05 does not permit', async () => {
    await expect(saveProfile(ada.id, { handle: 'ada@example' })).rejects.toBeInstanceOf(
      InvalidHandleError,
    )
  })

  // The distinction this whole partial-update shape exists for.
  it('leaves the handle alone when the update does not mention it', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    const profile = await saveProfile(ada.id, { picture: 'https://example.test/a.png' })

    expect(profile.handle).toBe('ada')
    expect(profile.picture).toBe('https://example.test/a.png')
  })

  it('clears the handle when it is explicitly null', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    const profile = await saveProfile(ada.id, { handle: null })

    expect(profile.handle).toBeNull()
    expect(nip05Value(profile)).toBeUndefined()
  })
})

describe('publishProfile', () => {
  it('publishes a signed kind:0 carrying the assembled handle', async () => {
    await saveProfile(ada.id, { handle: 'ada', picture: 'https://example.test/a.png' })
    const calls = stubRelay({ body: { accepted: true, event_id: 'abc' } })

    const outcome = await publishProfile(ada.id)

    expect(outcome.published).toBe(true)
    expect(calls).toHaveLength(1)
    expect(calls[0]?.url).toBe('https://estiva.estiva.app/events')
    expect(calls[0]?.authorization).toMatch(/^Nostr /)

    const event = calls[0]?.body as { kind: number; pubkey: string; content: string }
    expect(event.kind).toBe(0)
    expect(event.pubkey).toBe(ada.pubkey)
    expect(JSON.parse(event.content)).toMatchObject({
      display_name: 'Ada',
      name: 'Ada',
      nip05: `ada@${HOST}`,
      picture: 'https://example.test/a.png',
    })
  })

  /**
   * Offboarding depends on this: revoking a handle is republishing without it.
   * Measured against the live relay — omitting the field revokes.
   */
  it('publishes a profile with no nip05 once the handle is cleared', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    await saveProfile(ada.id, { handle: null })
    const calls = stubRelay({ body: { accepted: true, event_id: 'abc' } })

    await publishProfile(ada.id)

    const event = calls[0]?.body as { content: string }
    expect(event.content).not.toContain('nip05')
  })

  // HTTP 200 with accepted:false is how the relay declines. Treating the status
  // code as the answer would record a rejection as a success.
  it('treats accepted:false on a 200 as a failure, not a success', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    stubRelay({ body: { accepted: false, message: 'rejected: bad handle domain' } })

    const outcome = await publishProfile(ada.id)

    expect(outcome.published).toBe(false)
    expect(outcome.reason).toContain('rejected')
  })

  it('treats a duplicate as the desired end state', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    stubRelay({ body: { accepted: false, message: 'duplicate: already have it', event_id: 'abc' } })

    expect((await publishProfile(ada.id)).published).toBe(true)
  })

  // The relay is a projection of what Postgres holds, so an outage should leave
  // the projection stale — never lose the edit that was already committed.
  it('does not lose the saved profile when the relay is unreachable', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error('ECONNREFUSED')
      }),
    )

    const outcome = await publishProfile(ada.id)

    expect(outcome.published).toBe(false)
    expect((await getProfile(ada.id))?.handle).toBe('ada')
  })

  it('records every publish attempt in the audit log', async () => {
    await saveProfile(ada.id, { handle: 'ada' })
    stubRelay({ body: { accepted: true, event_id: 'abc' } })

    await publishProfile(ada.id)

    const rows = await query<{ outcome: string; detail: Record<string, unknown> }>(
      "select outcome, detail from audit_events where action = 'profile.publish'",
    )
    expect(rows.rows).toHaveLength(1)
    expect(rows.rows[0]?.outcome).toBe('success')
    expect(rows.rows[0]?.detail.nip05).toBe(`ada@${HOST}`)
  })
})
