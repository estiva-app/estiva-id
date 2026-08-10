/**
 * PEEK-67: getting somebody back in without giving them a new identity.
 *
 * Two properties carry the whole feature, and both are checked here rather than
 * reasoned about:
 *
 *   * **The pubkey survives.** If it does not, everything the person ever signed
 *     detaches from them, and recovery becomes a slower way of losing the
 *     account. This is the one assertion the feature exists for.
 *   * **The old passkeys stop working.** "Lost every device" usually means
 *     somebody else has one, so a recovery that leaves the previous credentials
 *     live restores access to the wrong person as well.
 *
 * The rest is the shape of a bearer link that opens an existing account, which
 * is strictly more dangerous than an invite and is treated accordingly.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { config } from '../../config.js'
import { closePool, query, queryOne } from '../../db/pool.js'
import { listAudit } from '../../domain/audit-log.js'
import { listCredentialSummaries } from '../../domain/credentials.js'
import { getActivePubkey } from '../../domain/keys.js'
import { createRecovery } from '../../domain/recovery.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { SoftwareAuthenticator } from '../../test/authenticator.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()
const cfg = config()

const post = (path: string, body: unknown, cookie?: string) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body ?? {}),
  })

const device = () =>
  new SoftwareAuthenticator({ rpId: cfg.RP_ID, origin: cfg.RP_ORIGINS[0] as string })

async function signedInAs(email: string, role: 'admin' | 'member') {
  const user = await createUserWithKey({ email, role })
  const { token } = await createSession({ userId: user.id })
  return { user, cookie: `estiva_id_session=${token}` }
}

/** Enrol a passkey through the recovery link, as the person would. */
async function redeem(token: string) {
  const authenticator = device()
  const options = (await (
    await post('/auth/recover/options', { recoveryToken: token })
  ).json()) as {
    challenge: string
  }
  return post('/auth/recover/verify', authenticator.register(options.challenge))
}

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
})

afterAll(async () => {
  await closePool()
})

describe('what recovery preserves', () => {
  it('keeps the pubkey, which is the entire point', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const before = await getActivePubkey(lost.id)
    expect(before).toBeTruthy()

    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    const response = await redeem(recovery.token)
    expect(response.status).toBe(200)

    expect(await getActivePubkey(lost.id)).toBe(before)
    expect(((await response.json()) as { pubkey: string }).pubkey).toBe(before)
  })

  it('signs the person straight in, so recovery is one step and not two', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })

    const response = await redeem(recovery.token)
    expect(response.headers.get('set-cookie')).toContain('estiva_id_session=')
  })

  it('does not create a second identity for the same person', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    await redeem(recovery.token)

    const users = await queryOne<{ count: string }>('select count(*)::text as count from users')
    expect(users?.count).toBe('1')
  })
})

describe('what recovery takes away', () => {
  /**
   * The device that was lost is usually in somebody's hands, so leaving its
   * passkey live restores access to them too. Retiring happens at redemption
   * rather than at issuance: a person who turns out to still have a working
   * device and never clicks the link is left exactly as they were.
   */
  it('retires every earlier passkey, keeping only the new one', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })

    // Two devices they can no longer reach.
    for (const _ of [0, 1]) {
      await query(
        `insert into webauthn_credentials (user_id, credential_id, public_key, sign_count)
         values ($1, $2, $3, 0)`,
        [lost.id, Buffer.from(`old-${Math.random()}`), Buffer.from('key')],
      )
    }
    expect(await listCredentialSummaries(lost.id)).toHaveLength(2)

    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    const response = await redeem(recovery.token)
    expect(response.status).toBe(200)
    expect(((await response.json()) as { passkeysRetired: number }).passkeysRetired).toBe(2)

    const active = await listCredentialSummaries(lost.id)
    expect(active).toHaveLength(1)
  })

  it('leaves the person with a working passkey, never zero', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    await redeem(recovery.token)

    expect(await listCredentialSummaries(lost.id)).toHaveLength(1)
  })
})

describe('the link', () => {
  it('is single use', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })

    expect((await redeem(recovery.token)).status).toBe(200)

    const again = await post('/auth/recover/options', { recoveryToken: recovery.token })
    expect(again.status).toBe(403)
    expect(await again.text()).toContain('already been used')
  })

  it('expires', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    await query("update recovery_tokens set expires_at = now() - interval '1 hour'")

    const response = await post('/auth/recover/options', { recoveryToken: recovery.token })
    expect(response.status).toBe(403)
    expect(await response.text()).toContain('expired')
  })

  it('is refused when it was never issued', async () => {
    const response = await post('/auth/recover/options', { recoveryToken: 'not-a-real-token' })
    expect(response.status).toBe(403)
  })

  // Issuing again supersedes, so a link sent to the wrong person can be undone
  // by issuing another rather than by finding a way to revoke the first.
  it('is superseded by issuing another', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const first = await createRecovery({ userId: lost.id, createdBy: null })
    await createRecovery({ userId: lost.id, createdBy: null })

    const response = await post('/auth/recover/options', { recoveryToken: first.token })
    expect(response.status).toBe(403)
  })

  // Survives an abandoned browser prompt, like an invite: dismissing the
  // dialog is the commonest failure and should not cost a call to the admin.
  it('survives an abandoned attempt', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })

    expect((await post('/auth/recover/options', { recoveryToken: recovery.token })).status).toBe(
      200,
    )
    expect((await post('/auth/recover/options', { recoveryToken: recovery.token })).status).toBe(
      200,
    )
  })
})

describe('who can be recovered', () => {
  /**
   * The dangerous case. Offboarding revokes every passkey, so "restore their
   * passkey" is exactly the shape of the mistake — recovery must not be a way
   * back in that bypasses the decision to take access away.
   */
  it('refuses an offboarded identity', async () => {
    const gone = await createUserWithKey({ email: 'gone@example.test' })
    await setUserStatus(gone.id, 'offboarded')

    await expect(createRecovery({ userId: gone.id, createdBy: null })).rejects.toThrow()
  })

  it('refuses a link issued before the person was offboarded', async () => {
    const gone = await createUserWithKey({ email: 'gone@example.test' })
    const recovery = await createRecovery({ userId: gone.id, createdBy: null })

    // The later decision wins, even though the link was valid when minted.
    await setUserStatus(gone.id, 'offboarded')

    const response = await post('/auth/recover/options', { recoveryToken: recovery.token })
    expect(response.status).toBe(403)
    expect(await response.text()).toContain('no longer active')
  })
})

describe('the recovery challenge', () => {
  /**
   * `/auth/register/verify` inserts a credential and stops — it neither retires
   * the old passkeys nor burns the link. A recovery redeemed through it would
   * leave a live link and a lost device that still works, so the ceremonies are
   * kept distinct and this is what proves they are.
   */
  it('cannot be redeemed at the ordinary registration route', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    const authenticator = device()

    const options = (await (
      await post('/auth/recover/options', { recoveryToken: recovery.token })
    ).json()) as { challenge: string }

    const wrongRoute = await post(
      '/auth/register/verify',
      authenticator.register(options.challenge),
    )
    expect(wrongRoute.status).toBe(400)

    // And the link is still unused, so the real route still works.
    expect((await redeem(recovery.token)).status).toBe(200)
  })
})

describe('issuing a link', () => {
  it('needs an admin', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const { cookie } = await signedInAs('member@example.test', 'member')

    const response = await post(`/admin/people/${lost.id}/recovery`, {}, cookie)
    expect(response.status).toBe(403)
  })

  it('gives the admin a link and an expiry, and records it without the token', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const { cookie } = await signedInAs('admin@example.test', 'admin')

    const response = await post(`/admin/people/${lost.id}/recovery`, {}, cookie)
    expect(response.status).toBe(200)

    const body = (await response.json()) as { url: string; expiresAt: string }
    expect(body.url).toContain('?recover=')
    expect(Date.parse(body.expiresAt)).toBeGreaterThan(Date.now())

    const audit = await queryOne<{ detail: Record<string, unknown> }>(
      "select detail from audit_events where action = 'recovery.issue'",
    )
    expect(audit?.detail).toMatchObject({ subjectUserId: lost.id })
    // A log read by every admin must not carry a credential that takes over an
    // account.
    expect(JSON.stringify(audit?.detail)).not.toContain(body.url.split('?recover=')[1] as string)
  })

  /**
   * An admin with a session can already add a device from their account page,
   * so asking for a link for themselves is either a misunderstanding or
   * somebody with a stolen session widening their foothold.
   */
  it('refuses an admin recovering themselves', async () => {
    const { user, cookie } = await signedInAs('admin@example.test', 'admin')

    const response = await post(`/admin/people/${user.id}/recovery`, {}, cookie)
    expect(response.status).toBe(400)
  })

  /**
   * The record has to reach the person, not merely exist.
   *
   * `listAudit` resolves its subject through `subject_pubkey` against
   * `user_keys`; a `subjectUserId` buried in the detail is not indexed and
   * nothing joins on it. Without the pubkey the issue event was written
   * correctly, said the right thing, and appeared on nobody's account page —
   * which is precisely the failure this ticket exists to prevent, since an
   * admin issuing a link and an admin taking an account differ only in whether
   * the person can see it.
   */
  it('shows the issued link to the person it was issued for', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const { cookie: adminCookie } = await signedInAs('admin@example.test', 'admin')
    await post(`/admin/people/${lost.id}/recovery`, {}, adminCookie)

    const events = await listAudit({ userId: lost.id })
    expect(events.map((entry) => entry.action)).toContain('recovery.issue')
  })

  it('records the redemption, saying the pubkey did not change', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })
    await redeem(recovery.token)

    const audit = await queryOne<{ outcome: string; detail: Record<string, unknown> }>(
      "select outcome, detail from audit_events where action = 'recovery.complete'",
    )
    expect(audit?.outcome).toBe('success')
    expect(audit?.detail).toMatchObject({ pubkeyUnchanged: true, consumed: true })
  })
})

describe('the preview', () => {
  // A link forwarded to the wrong colleague should be obvious to them, not
  // only to whoever issued it.
  it('says whose account the link opens', async () => {
    const lost = await createUserWithKey({ email: 'ada@example.test', displayName: 'Ada' })
    const recovery = await createRecovery({ userId: lost.id, createdBy: null })

    const response = await app.request(`/recovery/${recovery.token}`)
    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({
      ok: true,
      recovery: { email: 'ada@example.test', displayName: 'Ada' },
    })
  })

  it('answers 404 for a link that is not usable', async () => {
    const response = await app.request('/recovery/not-a-real-token')
    expect(response.status).toBe(404)
  })
})
