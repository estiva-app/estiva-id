/**
 * PEEK-30: the private directory.
 *
 * The load-bearing claim is a negative one — that an email is readable here and
 * exists nowhere on the relay — so that is checked against the actual `kind:0`
 * this service builds, not asserted in prose.
 *
 * The CORS headers are checked here too, but **that is not the verification
 * that counts**. Nothing enforces CORS when a Hono app is called in-process;
 * these assertions confirm the header is emitted, and a browser on a second
 * origin confirms the feature works. PEEK-90 shipped green tests and a broken
 * feature on exactly this distinction.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { publishProfile } from '../../domain/profile.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

const ORIGIN = 'http://localhost:5190'

async function member(email: string, role: 'admin' | 'member' = 'member') {
  const user = await createUserWithKey({ email, displayName: email.split('@')[0], role })
  const { token } = await issueToken({ pubkey: user.pubkey, clientId: 'estiva-peek' })
  return { ...user, token }
}

const lookup = (token: string, pubkeys: string[], origin?: string) =>
  app.request('/directory/lookup', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      ...(origin ? { origin } : {}),
    },
    body: JSON.stringify({ pubkeys }),
  })

beforeAll(async () => {
  process.env.COMMUNITY_HOST = 'estiva.test'
  process.env.RELAY_BRIDGE_URL = 'https://relay.test'
  const { resetConfigForTests } = await import('../../config.js')
  resetConfigForTests()
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  // The CORS allowlist is the registered redirect URIs, so give the seeded app
  // one on the origin these tests speak from.
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [`${ORIGIN}/callback`],
    'estiva-peek',
  ])
})

afterAll(async () => {
  await closePool()
})

describe('the split this endpoint exists for', () => {
  /**
   * The whole point, stated as a test: the email is readable through the API
   * and absent from the event that goes to the relay. A private contact address
   * on a shared relay is unretractable, so this cannot be a matter of habit.
   */
  it('returns an email that the published profile does not contain', async () => {
    const caller = await member('caller@example.test')
    const ada = await member('ada@example.test')

    const response = await lookup(caller.token, [ada.pubkey])
    const { contacts } = (await response.json()) as { contacts: { email: string }[] }
    expect(contacts[0]?.email).toBe('ada@example.test')

    // Assert against what actually goes to the relay, captured from the real
    // publish path. Rebuilding the event here would only re-check this test's
    // own idea of which fields are published.
    let published = ''
    vi.stubGlobal('fetch', async (_input: unknown, init?: RequestInit) => {
      published = String(init?.body ?? '')
      return new Response(JSON.stringify({ accepted: true, event_id: 'x' }), { status: 200 })
    })
    await publishProfile(ada.id)
    vi.unstubAllGlobals()

    expect(published).not.toBe('')
    expect(published).not.toContain('ada@example.test')
    expect(published).not.toContain('@example.test')
    expect(JSON.parse(JSON.parse(published).content)).not.toHaveProperty('email')
  })

  it('carries name and role alongside it', async () => {
    const caller = await member('caller@example.test')
    const boss = await member('boss@example.test', 'admin')

    const { contacts } = (await (await lookup(caller.token, [boss.pubkey])).json()) as {
      contacts: { displayName: string; role: string; pubkey: string }[]
    }
    expect(contacts[0]).toMatchObject({
      pubkey: boss.pubkey,
      displayName: 'boss',
      role: 'admin',
    })
  })

  /**
   * A leaver's name and email still resolve — their old messages have to keep
   * rendering as written by a person — but the status says what they are now,
   * so an app is not forced to show them as a current colleague forever.
   */
  it('still resolves somebody who has left, and says so', async () => {
    const caller = await member('caller@example.test')
    const gone = await member('gone@example.test')
    await setUserStatus(gone.id, 'offboarded')

    const { contacts } = (await (await lookup(caller.token, [gone.pubkey])).json()) as {
      contacts: { email: string; status: string }[]
    }
    expect(contacts[0]).toMatchObject({ email: 'gone@example.test', status: 'offboarded' })
  })
})

describe('who may ask', () => {
  it('refuses a caller with no token', async () => {
    const ada = await member('ada@example.test')
    const response = await app.request('/directory/lookup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pubkeys: [ada.pubkey] }),
    })
    expect(response.status).toBe(401)
  })

  it('refuses a garbage token', async () => {
    const ada = await member('ada@example.test')
    expect((await lookup('not-a-jwt', [ada.pubkey])).status).toBe(401)
  })

  /**
   * Tokens live 600s and a leaver holds one until it expires. Without this
   * check the directory stays readable for ten minutes after an offboarding.
   */
  it('refuses a caller who has been offboarded, even with a live token', async () => {
    const leaver = await member('leaver@example.test')
    const ada = await member('ada@example.test')
    await setUserStatus(leaver.id, 'offboarded')

    expect((await lookup(leaver.token, [ada.pubkey])).status).toBe(403)
  })
})

describe('lookup, never listing', () => {
  it('answers only about the pubkeys it was given', async () => {
    const caller = await member('caller@example.test')
    const ada = await member('ada@example.test')
    await member('unrelated@example.test')

    const { contacts } = (await (await lookup(caller.token, [ada.pubkey])).json()) as {
      contacts: { email: string }[]
    }
    expect(contacts).toHaveLength(1)
    expect(contacts[0]?.email).toBe('ada@example.test')
  })

  /**
   * Absent, not a null entry. An explicit "no such person" for every key an app
   * has ever seen would make this a way to test which keys are members.
   */
  it('omits pubkeys that belong to nobody', async () => {
    const caller = await member('caller@example.test')
    const { contacts } = (await (await lookup(caller.token, ['a'.repeat(64)])).json()) as {
      contacts: unknown[]
    }
    expect(contacts).toHaveLength(0)
  })

  it('refuses a malformed pubkey rather than searching for it', async () => {
    const caller = await member('caller@example.test')
    expect((await lookup(caller.token, ['nope'])).status).toBe(400)
  })

  it('caps how many may be asked for at once', async () => {
    const caller = await member('caller@example.test')
    const many = Array.from({ length: 201 }, (_, i) => i.toString(16).padStart(64, '0'))
    expect((await lookup(caller.token, many)).status).toBe(400)
  })

  it('has no route that returns everybody', async () => {
    const caller = await member('caller@example.test')
    const response = await app.request('/directory', {
      headers: { authorization: `Bearer ${caller.token}` },
    })
    expect(response.status).toBe(404)
  })
})

describe('one person', () => {
  it('resolves a single pubkey', async () => {
    const caller = await member('caller@example.test')
    const ada = await member('ada@example.test')

    const response = await app.request(`/directory/${ada.pubkey}`, {
      headers: { authorization: `Bearer ${caller.token}` },
    })
    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({ email: 'ada@example.test' })
  })

  it('answers 404 for a pubkey nobody holds', async () => {
    const caller = await member('caller@example.test')
    const response = await app.request(`/directory/${'b'.repeat(64)}`, {
      headers: { authorization: `Bearer ${caller.token}` },
    })
    expect(response.status).toBe(404)
  })
})

/**
 * Emitted here, enforced by a browser. See the file docstring — these confirm
 * the header exists, not that the feature works.
 */
describe('cross-origin headers', () => {
  it('answers a preflight from a registered origin, allowing the Authorization header', async () => {
    const response = await app.request('/directory/lookup', {
      method: 'OPTIONS',
      headers: {
        origin: ORIGIN,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'authorization',
      },
    })
    expect(response.status).toBe(204)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(response.headers.get('access-control-allow-headers')).toContain('authorization')
  })

  it('refuses a preflight from an origin nobody registered', async () => {
    const response = await app.request('/directory/lookup', {
      method: 'OPTIONS',
      headers: { origin: 'https://attacker.example', 'access-control-request-method': 'POST' },
    })
    expect(response.status).toBe(403)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })

  /**
   * Never. Without it a browser will not attach the session cookie
   * cross-origin, which is what keeps cookie-authenticated routes
   * same-origin-only while this bearer-authenticated one works.
   */
  it('never allows credentials', async () => {
    const caller = await member('caller@example.test')
    const ada = await member('ada@example.test')

    const response = await lookup(caller.token, [ada.pubkey], ORIGIN)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    expect(response.headers.get('access-control-allow-credentials')).toBeNull()
    expect(response.headers.get('vary')).toContain('Origin')
  })

  it('does not echo an origin that is not registered', async () => {
    const caller = await member('caller@example.test')
    const ada = await member('ada@example.test')

    const response = await lookup(caller.token, [ada.pubkey], 'https://attacker.example')
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })
})
