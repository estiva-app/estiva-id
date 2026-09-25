/**
 * PER-22: a test account signs in with no person present, and nothing else can.
 *
 * The happy path proves the harness works. The refusals are what make a
 * password on an identity service acceptable: only a test account can hold
 * one, it cannot be an admin, and a wrong or revoked secret gets nothing.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query } from '../../db/pool.js'
import { createTestAccount, issueTestSecret } from '../../domain/test-accounts.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'
import { resetTestLoginRateLimitForTests } from './test-login.js'

const app = createApp()

const login = (email: string, secret: string) =>
  app.request('/auth/test-login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email, secret }),
  })

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
  resetTestLoginRateLimitForTests()
})

afterAll(async () => {
  await closePool()
})

describe('test accounts', () => {
  it('signs in with its secret and gets an ordinary member session', async () => {
    const qa = await createTestAccount({ email: 'qa-1@example.test', displayName: 'QA-1' })

    const response = await login('QA-1@example.test', qa.secret)
    expect(response.status).toBe(200)
    const body = (await response.json()) as { pubkey: string; session_token: string }
    expect(body.pubkey).toBe(qa.pubkey)
    expect(response.headers.get('set-cookie')).toContain('estiva_id_session=')

    // A person in every way the account page can see — not delegated, a member.
    const me = await app.request('/me', {
      headers: { cookie: `estiva_id_session=${body.session_token}` },
    })
    expect(await me.json()).toMatchObject({ pubkey: qa.pubkey, role: 'member' })
    const profile = await app.request('/me/profile', {
      headers: { cookie: `estiva_id_session=${body.session_token}` },
    })
    expect(profile.status).toBe(200)
  })

  it('refuses a wrong secret, and a rotated-away one', async () => {
    const qa = await createTestAccount({ email: 'qa-1@example.test', displayName: 'QA-1' })
    expect((await login('qa-1@example.test', 'wrong')).status).toBe(401)

    await issueTestSecret(qa.userId)
    expect((await login('qa-1@example.test', qa.secret)).status).toBe(401)
  })

  it('refuses an offboarded test account', async () => {
    const qa = await createTestAccount({ email: 'qa-1@example.test', displayName: 'QA-1' })
    await query(`update users set status = 'offboarded' where id = $1`, [qa.userId])
    expect((await login('qa-1@example.test', qa.secret)).status).toBe(401)
  })

  it('cannot give a real person a secret', async () => {
    const person = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    await expect(issueTestSecret(person.id)).rejects.toThrow(/foreign key/)
  })

  it('cannot turn a test account into an admin, or back into a person', async () => {
    const qa = await createTestAccount({ email: 'qa-1@example.test', displayName: 'QA-1' })
    await expect(
      query(`update users set role = 'admin' where id = $1`, [qa.userId]),
    ).rejects.toThrow(/users_test_account_is_a_member/)
    await expect(
      query('update users set test_account = false where id = $1', [qa.userId]),
    ).rejects.toThrow(/foreign key/)
  })
})
