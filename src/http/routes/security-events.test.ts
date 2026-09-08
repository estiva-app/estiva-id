/**
 * `/me/security-events` — your own access history (PEEK-67).
 *
 * **The endpoint had no tests, and that is why it answered nothing in
 * production for weeks.** Reported as "I never get recent activity in Estiva ID.
 * I once or twice saw some logs but they disappear", which is exactly what a
 * page-then-filter bug looks like from outside.
 *
 * It asked for the newest 50 rows for the person and then kept the ones in
 * `SELF_VISIBLE_ACTIONS`. But every `POST /sign` writes `sign.granted` and every
 * `POST /token` writes `token.issue`/`token.exchange`/`token.refresh` — and Peek
 * and Ship sign every message, reaction, edit and read-state publish. So an
 * ordinary account's newest 50 rows are all app traffic, every interesting
 * action is older than the window, and the answer is `[]`.
 *
 * The intermittency is the tell, and the reason it was never obviously broken:
 * straight after signing in, the `session.create` is still inside the window.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool } from '../../db/pool.js'
import { recordAudit } from '../../domain/audit.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

interface Event {
  action: string
  outcome: string
  bySomeoneElse: boolean
  actorEmail: string | null
}

async function signedIn(email = 'member@example.test') {
  const user = await createUserWithKey({ email })
  const { token } = await createSession({ userId: user.id })
  return { user, cookie: `estiva_id_session=${token}` }
}

const events = async (cookie: string) => {
  const response = await app.request('/me/security-events', { headers: { cookie } })
  const body = (await response.json()) as { events: Event[] }
  return { status: response.status, events: body.events }
}

/** What an app does constantly, and what used to bury everything else. */
async function appTraffic(pubkey: string, count: number) {
  for (let i = 0; i < count; i++) {
    await recordAudit({
      actorType: 'app',
      actorClientId: 'estiva-peek',
      action: i % 3 === 0 ? 'token.issue' : 'sign.granted',
      outcome: 'success',
      subjectPubkey: pubkey,
    })
  }
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

describe('your own access history', () => {
  it('requires a session', async () => {
    expect((await app.request('/me/security-events')).status).toBe(401)
  })

  it('shows the actions that concern your access', async () => {
    const { user, cookie } = await signedIn()
    await recordAudit({
      actorType: 'user',
      actorUserId: user.id,
      action: 'passkey.register',
      outcome: 'success',
      subjectPubkey: user.pubkey,
    })

    const { status, events: list } = await events(cookie)
    expect(status).toBe(200)
    expect(list.map((e) => e.action)).toContain('passkey.register')
  })

  it('never shows app traffic, however much of it there is', async () => {
    // `sign.granted` and `token.*` are not this person's access history. They
    // are an app doing its job, and there are thousands of them.
    const { user, cookie } = await signedIn()
    await appTraffic(user.pubkey, 5)

    const { events: list } = await events(cookie)
    expect(list).toEqual([])
  })

  it('STILL shows a passkey enrolment buried under 60 signatures', async () => {
    /*
      The regression. Sixty is past the 50-row page, so under the old
      page-then-filter this returned `[]` — which is what production did.
    */
    const { user, cookie } = await signedIn()
    await recordAudit({
      actorType: 'user',
      actorUserId: user.id,
      action: 'passkey.register',
      outcome: 'success',
      subjectPubkey: user.pubkey,
    })
    await appTraffic(user.pubkey, 60)

    const { events: list } = await events(cookie)
    expect(list.map((e) => e.action)).toEqual(['passkey.register'])
  })

  it('names the admin when somebody else acted on your account', async () => {
    // The whole point of PEEK-67: a recovery run by an admin is mechanically
    // identical to an admin taking the account, and only the trail tells the
    // person it happened to. "An admin" is not something anybody can follow up.
    const { user, cookie } = await signedIn()
    const admin = await createUserWithKey({ email: 'admin@example.test', role: 'admin' })
    await recordAudit({
      actorType: 'user',
      actorUserId: admin.id,
      action: 'recovery.issue',
      outcome: 'success',
      subjectPubkey: user.pubkey,
    })
    await appTraffic(user.pubkey, 60)

    const { events: list } = await events(cookie)
    expect(list).toHaveLength(1)
    expect(list[0]?.bySomeoneElse).toBe(true)
    expect(list[0]?.actorEmail).toBe('admin@example.test')
  })

  it('shows nothing of somebody else’s history', async () => {
    const { cookie } = await signedIn('me@example.test')
    const other = await createUserWithKey({ email: 'other@example.test' })
    await recordAudit({
      actorType: 'user',
      actorUserId: other.id,
      action: 'passkey.register',
      outcome: 'success',
      subjectPubkey: other.pubkey,
    })

    expect((await events(cookie)).events).toEqual([])
  })
})
