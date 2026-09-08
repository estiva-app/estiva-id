/**
 * PEEK-28 and PEEK-71 acceptance, over HTTP.
 *
 * PEEK-28: *"the service refuses to sign for a pubkey the caller is not
 * authenticated as."*
 * PEEK-71: *"an app asking to sign a kind outside its list is refused, and the
 * refusal is logged."*
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query, queryOne } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { createUserWithKey } from '../../domain/users.js'
import { verifyEvent } from '../../nostr/keys.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

async function sign(token: string, event: Record<string, unknown>): Promise<Response> {
  return app.request('/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ event }),
  })
}

async function auditRows(action: string) {
  const result = await query<{ action: string; outcome: string; detail: Record<string, unknown> }>(
    'select action, outcome, detail from audit_events where action = $1 order by id',
    [action],
  )
  return result.rows
}

let ada: Awaited<ReturnType<typeof createUserWithKey>>
let peekToken: string
let shipToken: string

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  ada = await createUserWithKey({ email: 'ada@example.test' })
  peekToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
  shipToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-ship' })).token
})

afterAll(async () => {
  await closePool()
})

describe('signing', () => {
  it('signs an allowed kind and returns a verifiable event', async () => {
    const response = await sign(peekToken, { kind: 9, tags: [['h', 'channel']], content: 'hello' })
    expect(response.status).toBe(200)

    const { event } = (await response.json()) as { event: Parameters<typeof verifyEvent>[0] }
    expect(event.pubkey).toBe(ada.pubkey)
    expect(event.sig).toMatch(/^[0-9a-f]{128}$/)
    expect(verifyEvent(event)).toBe(true)
  })

  it('never returns the secret key', async () => {
    const response = await sign(peekToken, { kind: 9, tags: [], content: 'hi' })
    const body = await response.text()
    expect(body).not.toMatch(/secret|privkey|private_key/i)
    expect(Object.keys(JSON.parse(body).event).sort()).toEqual([
      'content',
      'created_at',
      'id',
      'kind',
      'pubkey',
      'sig',
      'tags',
    ])
  })

  it('defaults created_at when the caller omits it', async () => {
    const before = Math.floor(Date.now() / 1000)
    const response = await sign(peekToken, { kind: 9, tags: [], content: 'hi' })
    const { event } = (await response.json()) as { event: { created_at: number } }
    expect(event.created_at).toBeGreaterThanOrEqual(before)
  })
})

describe('a caller may only sign as itself', () => {
  // The PEEK-28 done-when. A caller that names someone else's pubkey gets its
  // own signature, not theirs — the field is not an instruction.
  it('ignores a pubkey supplied in the request body', async () => {
    const mallory = await createUserWithKey({ email: 'mallory@example.test' })

    const response = await sign(peekToken, {
      kind: 9,
      tags: [],
      content: 'not from mallory',
      pubkey: mallory.pubkey,
    })

    expect(response.status).toBe(200)
    const { event } = (await response.json()) as { event: { pubkey: string } }
    expect(event.pubkey).toBe(ada.pubkey)
    expect(event.pubkey).not.toBe(mallory.pubkey)
  })

  it('refuses a request with no token', async () => {
    const response = await app.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ event: { kind: 9, tags: [], content: 'hi' } }),
    })
    expect(response.status).toBe(401)
  })

  it('refuses a token signed by somebody else', async () => {
    const forged = [
      Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'nope' })).toString('base64url'),
      Buffer.from(JSON.stringify({ sub: ada.pubkey, aud: 'estiva-peek' })).toString('base64url'),
      'not-a-signature',
    ].join('.')

    expect((await sign(forged, { kind: 9, tags: [], content: 'hi' })).status).toBe(401)
  })

  it('refuses once the identity has no active key', async () => {
    await query("update user_keys set status = 'revoked' where user_id = $1", [ada.id])
    expect((await sign(peekToken, { kind: 9, tags: [], content: 'hi' })).status).toBe(403)
  })
})

describe('per-app policy (PEEK-71)', () => {
  it('refuses a kind outside the calling app’s list', async () => {
    // 30850 is Linear-lite's kind. Peek's token must not reach it.
    const response = await sign(peekToken, { kind: 30850, tags: [], content: '' })
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'policy_violation', detail: { reason: 'kind_not_allowed' } },
    })
  })

  it('signs Peek’s own assertion kind', async () => {
    // PEEK-128. Asserted through the endpoint rather than against SEED_APPS,
    // because the seeded constant being right is not the same fact as the
    // running policy accepting the event — the row has to have been re-seeded.
    expect((await sign(peekToken, { kind: 9101, tags: [], content: '' })).status).toBe(200)
  })

  it('applies the calling app’s policy, not the other app’s', async () => {
    expect((await sign(shipToken, { kind: 30850, tags: [], content: '' })).status).toBe(200)
    expect((await sign(peekToken, { kind: 30850, tags: [], content: '' })).status).toBe(422)
  })

  it('refuses kind:0 for every app', async () => {
    for (const token of [peekToken, shipToken]) {
      const response = await sign(token, { kind: 0, tags: [], content: '{"name":"impostor"}' })
      expect(response.status).toBe(422)
      await expect(response.json()).resolves.toMatchObject({
        error: { detail: { reason: 'kind_profile_forbidden' } },
      })
    }
  })

  it('refuses NIP-98 for a destination that is not allowlisted', async () => {
    await query(
      "update app_credentials set allowed_kinds = allowed_kinds || 27235 where client_id = 'estiva-peek'",
    )
    const response = await sign(peekToken, {
      kind: 27235,
      tags: [
        ['u', 'https://evil.test/steal'],
        ['method', 'GET'],
      ],
      content: '',
    })
    expect(response.status).toBe(422)
  })
})

describe('audit (PEEK-69)', () => {
  it('logs a successful signature', async () => {
    await sign(peekToken, { kind: 9, tags: [], content: 'hi' })
    const rows = await auditRows('sign.granted')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ outcome: 'success', detail: { kind: 9 } })
  })

  // "…and the refusal is logged."
  it('logs a refusal with its reason', async () => {
    await sign(peekToken, { kind: 0, tags: [], content: '' })
    const rows = await auditRows('sign.refused')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({
      outcome: 'refused',
      detail: { reason: 'kind_profile_forbidden', kind: 0 },
    })
  })

  it('records no event content in the audit trail', async () => {
    await sign(peekToken, { kind: 9, tags: [], content: 'commercially sensitive' })
    const row = await queryOne<{ detail: Record<string, unknown> }>(
      "select detail from audit_events where action = 'sign.granted'",
    )
    expect(JSON.stringify(row?.detail)).not.toContain('commercially sensitive')
  })
})

describe('NIP-98 once the deployment allows the relay', () => {
  // The test environment allows http://relay.test/ (src/test/setup.ts), and the
  // seed gives each app the deployment's own prefixes — so this exercises the
  // configuration apps will actually run with, not a hand-built policy row.
  const httpAuth = (url: string) => ({
    kind: 27235,
    tags: [
      ['u', url],
      ['method', 'POST'],
    ],
    content: '',
  })

  it('signs a NIP-98 event for the relay bridge', async () => {
    const response = await sign(peekToken, httpAuth('http://relay.test/events'))
    expect(response.status).toBe(200)

    const { event } = (await response.json()) as { event: Parameters<typeof verifyEvent>[0] }
    expect(event.kind).toBe(27235)
    expect(verifyEvent(event)).toBe(true)
  })

  // Being open for the relay must not make it open generally — this is the
  // whole reason the URL constraint exists rather than just allowing the kind.
  it('still refuses a NIP-98 event for anywhere else', async () => {
    const response = await sign(peekToken, httpAuth('https://evil.test/steal'))
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'nip98_url_not_allowed' } },
    })
  })

  it('refuses a NIP-98 event with no destination at all', async () => {
    const response = await sign(peekToken, { kind: 27235, tags: [['method', 'POST']], content: '' })
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'nip98_missing_url' } },
    })
  })
})

/**
 * PEEK-93: `/sign` shipped with no CORS at all, so Ship's `estivaIdSigner` —
 * a browser `fetch` with a Bearer header, therefore preflighted — could never
 * reach it.
 *
 * **These assertions are not the verification that counts.** Nothing enforces
 * CORS when a Hono app is called in-process, which is exactly why the bug
 * survived a full passing suite twice. They pin the headers; a browser on a
 * second origin proves the feature.
 */
describe('cross-origin (PEEK-93)', () => {
  const ORIGIN = 'http://localhost:5190'

  beforeEach(async () => {
    await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
      [`${ORIGIN}/callback`],
      'estiva-peek',
    ])
  })

  it('answers a preflight from a registered origin, allowing the Authorization header', async () => {
    const response = await app.request('/sign', {
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
    const response = await app.request('/sign', {
      method: 'OPTIONS',
      headers: { origin: 'https://attacker.example', 'access-control-request-method': 'POST' },
    })
    expect(response.status).toBe(403)
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })

  it('echoes the origin on a successful signature, and never allows credentials', async () => {
    const response = await app.request('/sign', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${peekToken}`,
        origin: ORIGIN,
      },
      body: JSON.stringify({ event: { kind: 9, tags: [], content: 'hello' } }),
    })
    expect(response.status).toBe(200)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    // Never. Without it the browser will not attach the session cookie
    // cross-origin, which is what keeps the cookie same-origin-only.
    expect(response.headers.get('access-control-allow-credentials')).toBeNull()
    expect(response.headers.get('vary')).toContain('Origin')
  })

  /**
   * The subtle half, and the reason `allowOrigin` runs before anything that can
   * throw. A refusal a browser will not let the app read turns "this app may
   * not sign that kind" into "network error" — which defeats the whole point of
   * this endpoint's `detail.reason` vocabulary.
   */
  it('keeps the header on a policy refusal, so the app can read why', async () => {
    const response = await app.request('/sign', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${peekToken}`,
        origin: ORIGIN,
      },
      // kind:0 — refused for every app, always.
      body: JSON.stringify({ event: { kind: 0, tags: [], content: '{}' } }),
    })
    expect(response.status).toBe(422)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'kind_profile_forbidden' } },
    })
  })

  it('keeps the header on an unauthenticated refusal too', async () => {
    const response = await app.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json', origin: ORIGIN },
      body: JSON.stringify({ event: { kind: 9, tags: [], content: 'hi' } }),
    })
    expect(response.status).toBe(401)
    expect(response.headers.get('access-control-allow-origin')).toBe(ORIGIN)
  })

  it('does not echo an origin that is not registered', async () => {
    const response = await app.request('/sign', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${peekToken}`,
        origin: 'https://attacker.example',
      },
      body: JSON.stringify({ event: { kind: 9, tags: [], content: 'hello' } }),
    })
    expect(response.headers.get('access-control-allow-origin')).toBeNull()
  })
})

describe('NIP-42 once the deployment allows the relay (PEE-4)', () => {
  // Same posture as the NIP-98 block above, and the same reason for testing it
  // here rather than only in `policy.test.ts`: the rule is a pure function, but
  // the *column* has to survive `seed.ts` → `findAppPolicy` → `evaluateSignPolicy`.
  // A `relay_auth_urls` missing from that SELECT would leave the field
  // undefined, and the endpoint would refuse every relay while every unit test
  // still passed.
  //
  // The test environment allows `ws://relay.test` with no trailing slash while
  // the events below carry one, so a round trip through here also proves the
  // normalization is applied on both sides.
  const relayAuth = (relay: string) => ({
    kind: 22242,
    tags: [
      ['relay', relay],
      ['challenge', 'a-challenge-from-the-relay'],
    ],
    content: '',
  })

  it('signs a challenge response for the deployment’s relay', async () => {
    const response = await sign(peekToken, relayAuth('ws://relay.test/'))
    expect(response.status).toBe(200)

    const { event } = (await response.json()) as { event: Parameters<typeof verifyEvent>[0] }
    expect(event.kind).toBe(22242)
    expect(verifyEvent(event)).toBe(true)
  })

  it('refuses a challenge from any other relay', async () => {
    const response = await sign(peekToken, relayAuth('wss://evil.test/'))
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'relay_auth_relay_not_allowed' } },
    })
  })

  it('refuses a 22242 with no relay tag', async () => {
    const response = await sign(peekToken, {
      kind: 22242,
      tags: [['challenge', 'a-challenge-from-the-relay']],
      content: '',
    })
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'relay_auth_missing_relay' } },
    })
  })

  it('signs a challenge response for Ship, now that it holds the kind', async () => {
    // This was its own inverse until LIV-2 — "refuses Ship, which is granted
    // neither the kind nor a relay" — because Ship opened no socket and so had
    // no challenge to answer. It does now, and the pair below is what the
    // reversal is actually asserting: the grant arrived with its scope.
    const response = await sign(shipToken, relayAuth('ws://relay.test/'))
    expect(response.status).toBe(200)

    const { event } = (await response.json()) as { event: Parameters<typeof verifyEvent>[0] }
    expect(event.kind).toBe(22242)
    expect(verifyEvent(event)).toBe(true)
  })

  it('refuses Ship a challenge from any other relay', async () => {
    // The half worth having. Ship holding 22242 is only safe because the column
    // bounds it, and the bound has to be read from *Ship's* row — an app that
    // passes because Peek's row happens to be right is the failure this whole
    // pairing exists to make impossible.
    const response = await sign(shipToken, relayAuth('wss://evil.test/'))
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'relay_auth_relay_not_allowed' } },
    })
  })

  it('refuses the kind once the row’s relays are cleared, without touching the kind', async () => {
    // The state a bare `22242` in `seed.ts` would have produced. It is the
    // column that decides, so emptying it must refuse even though the app still
    // holds the kind — this is the pairing the grant could not ship without.
    await query("update app_credentials set relay_auth_urls = '{}' where client_id = 'estiva-peek'")
    const response = await sign(peekToken, relayAuth('ws://relay.test/'))
    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'relay_auth_relay_not_allowed' } },
    })
  })

  it('does not let the row widen past the deployment’s list', async () => {
    await query(
      "update app_credentials set relay_auth_urls = '{wss://evil.test/}' where client_id = 'estiva-peek'",
    )
    expect((await sign(peekToken, relayAuth('wss://evil.test/'))).status).toBe(422)
  })
})
