/**
 * PEEK-88 — offboarding has to stop signing, not just stop logging in.
 *
 * Before this, marking someone `offboarded` blocked new logins and nothing
 * else: their session stayed valid, `/token` kept issuing JWTs, and `/sign`
 * kept signing. Not the accepted 10-minute window after offboarding — that one
 * is Convex's, and unavoidable because it validates tokens statelessly.
 * This was unbounded, on the one side that can actually check.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../db/pool.js'
import { issueToken } from '../domain/jwt.js'
import { createApp } from '../http/app.js'
import { prepareDatabase, truncateAll } from '../test/db.js'
import { requestToken, signIn } from '../test/token.js'
import { findSignerByPubkey } from './keys.js'
import { createSession, resolveSession } from './sessions.js'
import { createUserWithKey, findUserById, offboardUser, setUserStatus } from './users.js'

const app = createApp()

async function sign(token: string) {
  return app.request('/sign', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
    body: JSON.stringify({ event: { kind: 9, tags: [], content: 'still here?' } }),
  })
}

const REDIRECT = 'https://peek.test/callback'

/** A renewal with the refresh token their sign-in left: what outlives a JWT. */
function renew() {
  return requestToken(app, {
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: 'estiva-peek',
  })
}

/**
 * A fresh sign-in on their session, and the §5.2 error it ends in.
 * `invalid_request` means `/authorize` handed out no code at all; a code it
 * should not have issued would be refused later, as `invalid_grant`.
 */
async function signInRefusal() {
  const response = await signIn(app, cookie, 'estiva-peek', REDIRECT)
  return ((await response.json()) as { error?: string }).error
}

let user: Awaited<ReturnType<typeof createUserWithKey>>
let token: string
let cookie: string
let refreshToken: string

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  await query('update app_credentials set redirect_uris = $1 where client_id = $2', [
    [REDIRECT],
    'estiva-peek',
  ])
  user = await createUserWithKey({ email: 'leaver@example.test' })
  token = (await issueToken({ pubkey: user.pubkey, clientId: 'estiva-peek' })).token
  cookie = `estiva_id_session=${(await createSession({ userId: user.id })).token}`
  const signedIn = await signIn(app, cookie, 'estiva-peek', REDIRECT)
  refreshToken = ((await signedIn.json()) as { refresh_token: string }).refresh_token
})

afterAll(async () => {
  await closePool()
})

describe('while the person is active', () => {
  // The guard must not become a way to lock people out — a refusal that fires
  // on everyone would pass every other test in this file.
  it('signs and issues tokens as normal', async () => {
    expect((await sign(token)).status).toBe(200)
    expect((await renew()).status).toBe(200)
    expect((await signIn(app, cookie, 'estiva-peek', REDIRECT)).status).toBe(200)
  })
})

describe('once offboarded', () => {
  it('refuses to sign, even with a token issued moments earlier', async () => {
    await offboardUser(user.id)

    const response = await sign(token)
    expect(response.status).toBe(403)
    await expect(response.json()).resolves.toMatchObject({
      error: { message: 'That identity is no longer active' },
    })
  })

  // Without this the fix is cosmetic: the token expires, they renew with the
  // refresh token they still hold, or sign in again on the session, and get
  // another one.
  it('revokes their sessions, so they cannot obtain a fresh token', async () => {
    const { sessionsRevoked } = await offboardUser(user.id)
    expect(sessionsRevoked).toBe(1)

    expect((await renew()).status).toBe(400)
    expect(await signInRefusal()).toBe('invalid_request')
  })

  it('refuses a token even if a session somehow survives', async () => {
    // Belt and braces: status alone must be enough, without relying on the
    // revocation having reached every session.
    await query("update users set status = 'offboarded' where id = $1", [user.id])
    expect((await renew()).status).toBe(400)
    expect(await signInRefusal()).toBe('invalid_request')
  })

  it('records the refusal with a reason naming the status', async () => {
    await offboardUser(user.id)
    await sign(token)

    const rows = await query<{ detail: Record<string, unknown> }>(
      "select detail from audit_events where action = 'sign.refused' order by id desc limit 1",
    )
    expect(rows.rows[0]?.detail).toMatchObject({ reason: 'user_offboarded' })
  })

  // "No active key" and "this person has left" are different operational
  // events; collapsing them would make the audit log useless for the question
  // anyone actually asks it.
  it('distinguishes a departed person from a missing key', async () => {
    await offboardUser(user.id)
    await sign(token)
    await query("update user_keys set status = 'revoked' where user_id = $1", [user.id])
    await sign(token)

    const rows = await query<{ detail: Record<string, unknown> }>(
      "select detail from audit_events where action = 'sign.refused' order by id",
    )
    const reasons = rows.rows.map((r) => r.detail.reason)
    expect(reasons).toEqual(['user_offboarded', 'no_active_key'])
  })

  it('keeps the key active, so signed history stays attributable', async () => {
    await offboardUser(user.id)

    const signer = await findSignerByPubkey(user.pubkey)
    expect(signer).toMatchObject({ userId: user.id, userStatus: 'offboarded' })
  })
})

describe('suspension', () => {
  it('also stops signing, and says which status refused it', async () => {
    await setUserStatus(user.id, 'suspended')

    expect((await sign(token)).status).toBe(403)
    const rows = await query<{ detail: Record<string, unknown> }>(
      "select detail from audit_events where action = 'sign.refused' order by id desc limit 1",
    )
    expect(rows.rows[0]?.detail).toMatchObject({ reason: 'user_suspended' })
  })

  it('can be lifted, and signing resumes', async () => {
    await setUserStatus(user.id, 'suspended')
    expect((await sign(token)).status).toBe(403)

    await setUserStatus(user.id, 'active')
    expect((await sign(token)).status).toBe(200)

    expect((await findUserById(user.id))?.status).toBe('active')
    // Reinstating does not resurrect the sessions killed on the way out.
    expect(await resolveSession(cookie.split('=')[1] as string)).toBeUndefined()
  })
})
