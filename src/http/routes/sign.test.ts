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
let linearToken: string

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  ada = await createUserWithKey({ email: 'ada@example.test' })
  peekToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
  linearToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'linear-lite' })).token
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

  it('applies the calling app’s policy, not the other app’s', async () => {
    expect((await sign(linearToken, { kind: 30850, tags: [], content: '' })).status).toBe(200)
    expect((await sign(peekToken, { kind: 30850, tags: [], content: '' })).status).toBe(422)
  })

  it('refuses kind:0 for every app', async () => {
    for (const token of [peekToken, linearToken]) {
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
