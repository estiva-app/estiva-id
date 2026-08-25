/**
 * CRO-1 acceptance, over HTTP.
 *
 * *"A Peek browser session can round-trip a string through `/nip44/encrypt`
 * then `/nip44/decrypt` and get it back, an attempt to pass a peer pubkey is
 * refused, a disabled app is refused, and both calls appear in the audit log
 * without their contents."*
 *
 * `nip44.test.ts` in `src/nostr/` proves the cryptography against the reference
 * vectors. This file is about the seam: who may call it, as whom, how often,
 * and what is written down afterwards.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { issueToken } from '../../domain/jwt.js'
import { withUserSecretKey } from '../../domain/keys.js'
import { createUserWithKey } from '../../domain/users.js'
import { conversationKey, encrypt } from '../../nostr/nip44.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'
import { resetRateLimitForTests } from './nip44.js'

const app = createApp()

async function post(path: string, token: string, body: unknown): Promise<Response> {
  return app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  })
}

const encryptFor = (token: string, plaintext: string) =>
  post('/nip44/encrypt', token, { plaintext })
const decryptFor = (token: string, ciphertext: string) =>
  post('/nip44/decrypt', token, { ciphertext })

async function auditRows(action: string) {
  const result = await query<{ outcome: string; detail: Record<string, unknown> }>(
    'select outcome, detail from audit_events where action = $1 order by id',
    [action],
  )
  return result.rows
}

let ada: Awaited<ReturnType<typeof createUserWithKey>>
let peekToken: string

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  resetRateLimitForTests()
  ada = await createUserWithKey({ email: 'ada@example.test' })
  peekToken = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
})

afterAll(async () => {
  await closePool()
})

describe('the round trip', () => {
  it('encrypts and decrypts back to the same string', async () => {
    const encrypted = await encryptFor(peekToken, 'h:9f2c read at 1756000000')
    expect(encrypted.status).toBe(200)
    const { ciphertext } = (await encrypted.json()) as { ciphertext: string }

    const decrypted = await decryptFor(peekToken, ciphertext)
    expect(decrypted.status).toBe(200)
    expect(await decrypted.json()).toEqual({ plaintext: 'h:9f2c read at 1756000000' })
  })

  it('produces a payload the NIP-44 version byte identifies', async () => {
    const { ciphertext } = (await (await encryptFor(peekToken, 'x')).json()) as {
      ciphertext: string
    }
    expect(Buffer.from(ciphertext, 'base64')[0]).toBe(2)
  })

  it('never returns the same ciphertext twice for one plaintext', async () => {
    // A fresh nonce per call. Deterministic output would make read state
    // comparable across people without decrypting any of it.
    const first = (await (await encryptFor(peekToken, 'same')).json()) as { ciphertext: string }
    const second = (await (await encryptFor(peekToken, 'same')).json()) as { ciphertext: string }
    expect(first.ciphertext).not.toBe(second.ciphertext)
  })

  it('round-trips a multi-byte string unchanged', async () => {
    const plaintext = 'čeština 🦄 — read'
    const { ciphertext } = (await (await encryptFor(peekToken, plaintext)).json()) as {
      ciphertext: string
    }
    expect(await (await decryptFor(peekToken, ciphertext)).json()).toEqual({ plaintext })
  })

  it('uses the key the user actually holds', async () => {
    // The strongest statement of "self-encryption": a blob encrypted outside the
    // service, under `conversation_key(ada_priv, ada_pub)`, decrypts here. That
    // is the key NIP-RS specifies, not merely a key that is internally
    // consistent with itself.
    const outside = await withUserSecretKey(ada.id, (secretKey, pubkey) =>
      encrypt('written by the client', conversationKey(secretKey, pubkey)),
    )
    const response = await decryptFor(peekToken, outside)
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ plaintext: 'written by the client' })
  })
})

describe('self-encryption only', () => {
  // The done-when: "an attempt to pass a peer pubkey is refused". Refused, not
  // ignored — see the header of `nip44.ts`. An app that believes it encrypted to
  // a colleague must not receive a blob only the user can open.
  it('refuses an encrypt that names a peer', async () => {
    for (const extra of [{ pubkey: 'b'.repeat(64) }, { peer: 'b'.repeat(64) }, { to: 'someone' }]) {
      const response = await post('/nip44/encrypt', peekToken, { plaintext: 'hi', ...extra })
      expect(response.status, JSON.stringify(extra)).toBe(400)
    }
  })

  it('refuses a decrypt that names a peer', async () => {
    const { ciphertext } = (await (await encryptFor(peekToken, 'hi')).json()) as {
      ciphertext: string
    }
    const response = await post('/nip44/decrypt', peekToken, {
      ciphertext,
      pubkey: 'b'.repeat(64),
    })
    expect(response.status).toBe(400)
  })

  it('cannot open another person’s blob', async () => {
    const mallory = await createUserWithKey({ email: 'mallory@example.test' })
    const malloryBlob = await withUserSecretKey(mallory.id, (secretKey, pubkey) =>
      encrypt('mallory read this', conversationKey(secretKey, pubkey)),
    )

    // Ada's token, Mallory's blob. The endpoint takes no identity argument, so
    // there is nothing to point at Mallory — it fails on the MAC.
    const response = await decryptFor(peekToken, malloryBlob)
    expect(response.status).toBe(400)
    expect(await response.text()).not.toContain('mallory read this')
  })
})

describe('who may call it', () => {
  it('refuses a request with no token', async () => {
    const response = await app.request('/nip44/encrypt', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ plaintext: 'hi' }),
    })
    expect(response.status).toBe(401)
  })

  it('refuses a disabled app', async () => {
    await query("update app_credentials set status = 'disabled' where client_id = 'estiva-peek'")

    const response = await decryptFor(peekToken, (await outsideBlob()) as string)
    expect(response.status).toBe(422)
    expect(
      ((await response.json()) as { error: { detail: { reason: string } } }).error.detail.reason,
    ).toBe('app_disabled')

    expect((await auditRows('nip44.decrypt.refused'))[0]?.detail).toMatchObject({
      reason: 'app_disabled',
    })
  })

  it('refuses an offboarded person, whose token is still valid', async () => {
    // Tokens are stateless and live for JWT_TTL_SECONDS, so the row is the only
    // thing that can stop this — the same seam `/sign` documents.
    await query("update users set status = 'offboarded' where id = $1", [ada.id])
    const response = await encryptFor(peekToken, 'hi')
    expect(response.status).toBe(403)
  })

  it('refuses an unknown app credential', async () => {
    const token = (await issueToken({ pubkey: ada.pubkey, clientId: 'estiva-peek' })).token
    await query("delete from app_credentials where client_id = 'estiva-peek'")
    expect((await encryptFor(token, 'hi')).status).toBe(403)
  })
})

describe('rate limiting', () => {
  it('refuses past the window and says how long to wait', async () => {
    let last: Response | undefined
    for (let i = 0; i < 121; i++) last = await encryptFor(peekToken, 'x')

    expect(last?.status).toBe(429)
    expect(Number(last?.headers.get('retry-after'))).toBeGreaterThan(0)
    expect((await auditRows('nip44.encrypt.refused'))[0]?.detail).toMatchObject({
      reason: 'rate_limited',
    })
  })

  it('spends one budget across both endpoints', async () => {
    // One capability, one budget. A decrypt-only limit that reset whenever
    // encrypt was idle would bound nothing.
    const { ciphertext } = (await (await encryptFor(peekToken, 'x')).json()) as {
      ciphertext: string
    }
    for (let i = 0; i < 119; i++) await encryptFor(peekToken, 'x')

    expect((await decryptFor(peekToken, ciphertext)).status).toBe(429)
  })

  it('budgets each person separately', async () => {
    const bob = await createUserWithKey({ email: 'bob@example.test' })
    const bobToken = (await issueToken({ pubkey: bob.pubkey, clientId: 'estiva-peek' })).token

    for (let i = 0; i < 121; i++) await encryptFor(peekToken, 'x')
    expect((await encryptFor(bobToken, 'x')).status).toBe(200)
  })
})

describe('malformed input', () => {
  it('refuses a ciphertext that is not NIP-44 at all', async () => {
    for (const ciphertext of ['', 'not base64 at all!!', 'AAAA', 'a'.repeat(200)]) {
      expect((await decryptFor(peekToken, ciphertext)).status, ciphertext.slice(0, 20)).toBe(400)
    }
  })

  it('gives one answer for every decryption failure', async () => {
    // A caller that can tell a bad MAC from bad padding has a padding oracle.
    // The distinction is kept, but in the audit row rather than the response.
    const valid = (await (await encryptFor(peekToken, 'hi')).json()) as { ciphertext: string }
    // Flip the last byte of the MAC. `writeUInt8`/`readUInt8` rather than
    // indexing, because `noUncheckedIndexedAccess` types `buf[i]` as possibly
    // undefined and `pnpm typecheck` — which CI runs before the tests — says so.
    const tampered = Buffer.from(valid.ciphertext, 'base64')
    const last = tampered.length - 1
    tampered.writeUInt8(tampered.readUInt8(last) ^ 0xff, last)

    const bodies = await Promise.all(
      [tampered.toString('base64'), 'A'.repeat(132)].map(async (ciphertext) =>
        (await decryptFor(peekToken, ciphertext)).text(),
      ),
    )
    expect(JSON.parse(bodies[0] as string).error.message).toBe(
      JSON.parse(bodies[1] as string).error.message,
    )
    expect(JSON.parse(bodies[0] as string).error.detail.reason).toBe('undecryptable')
  })

  it('refuses an empty plaintext, which NIP-44 has no encoding for', async () => {
    expect((await encryptFor(peekToken, '')).status).toBe(400)
  })

  it('refuses a plaintext past 65535 bytes', async () => {
    expect((await encryptFor(peekToken, 'x'.repeat(65536))).status).toBe(400)
  })

  it('refuses a body with the wrong field entirely', async () => {
    expect((await post('/nip44/encrypt', peekToken, { ciphertext: 'x' })).status).toBe(400)
    expect((await post('/nip44/decrypt', peekToken, { plaintext: 'x' })).status).toBe(400)
  })
})

describe('the audit trail', () => {
  it('records both operations without their contents', async () => {
    const secret = 'this string must not appear in audit_events'
    const { ciphertext } = (await (await encryptFor(peekToken, secret)).json()) as {
      ciphertext: string
    }
    await decryptFor(peekToken, ciphertext)

    for (const action of ['nip44.encrypt.granted', 'nip44.decrypt.granted']) {
      const rows = await auditRows(action)
      expect(rows, action).toHaveLength(1)
      expect(rows[0]?.outcome).toBe('success')
    }

    // The whole table, not only the detail column — a length or a prefix
    // leaking through some other field would pass a narrower check.
    const everything = await query<{ row: string }>(
      'select audit_events::text as row from audit_events',
    )
    const dump = everything.rows.map((r) => r.row).join('\n')
    expect(dump).not.toContain(secret)
    expect(dump).not.toContain(ciphertext.slice(0, 24))
  })
})

/** A blob only Ada can open, made without going through the endpoint. */
async function outsideBlob(): Promise<string> {
  return withUserSecretKey(ada.id, (secretKey, pubkey) =>
    encrypt('outside', conversationKey(secretKey, pubkey)),
  )
}
