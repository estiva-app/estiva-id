/**
 * PEEK-34: identities that are not people.
 *
 * The distinction is load-bearing rather than cosmetic, and in two directions:
 *
 *   * **Stage 4 needs it.** Human custody is a temporary trade it unwinds; role
 *     custody is correct forever. Undifferentiated, the migration would find out
 *     which was which by breaking the ones it moved.
 *   * **Every human path must refuse a role.** A bot has no passkey, so anything
 *     that mints one for it — recovery above all — would hand whoever used it a
 *     permanent credential signing as the bot, with no human whose absence would
 *     ever be noticed.
 *
 * The signing half is the client-credentials grant, which is the first time this
 * service issues a token with no person anywhere in the flow.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool, query, queryOne } from '../../db/pool.js'
import { getActivePubkey } from '../../domain/keys.js'
import { offboardPerson } from '../../domain/offboarding.js'
import { createRecovery } from '../../domain/recovery.js'
import {
  MAX_BOTS_PER_PERSON,
  createRoleIdentity,
  issueServiceCredential,
} from '../../domain/roles.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { requestToken } from '../../test/token.js'
import { createApp } from '../app.js'

const app = createApp()

const post = (path: string, body: unknown, cookie?: string) =>
  app.request(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body ?? {}),
  })

const patch = (path: string, body: unknown, cookie?: string) =>
  app.request(path, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body ?? {}),
  })

async function signedInAs(email: string, role: 'admin' | 'member') {
  const user = await createUserWithKey({ email, role })
  const { token } = await createSession({ userId: user.id })
  return { user, cookie: `estiva_id_session=${token}` }
}

/** A role identity with a credential that can sign the kinds given. */
async function botWithCredential(kinds: number[] = [1]) {
  const bot = await createRoleIdentity({ displayName: 'Release Bot' })
  const credential = await issueServiceCredential({
    userId: bot.id,
    clientId: 'release-bot',
    name: 'Release Bot',
    allowedKinds: kinds,
  })
  return { bot, credential }
}

const tokenFor = (clientId: string, clientSecret: string) =>
  requestToken(app, {
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
  })

beforeAll(async () => {
  await prepareDatabase()
})

beforeEach(async () => {
  await truncateAll()
})

afterAll(async () => {
  await closePool()
})

describe('the data model', () => {
  it('marks a role identity as something other than a person', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    const row = await queryOne<{ kind: string }>('select kind from users where id = $1', [bot.id])
    expect(row?.kind).toBe('role')
  })

  it('still gives it a custodied key, because that is what it signs with', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    expect(await getActivePubkey(bot.id)).toMatch(/^[0-9a-f]{64}$/)
  })

  it('leaves people as people', async () => {
    const human = await createUserWithKey({ email: 'ada@example.test' })
    const row = await queryOne<{ kind: string }>('select kind from users where id = $1', [human.id])
    expect(row?.kind).toBe('human')
  })

  // A bot has no inbox. Requiring one would mean inventing addresses that
  // nothing delivers to, which is worse than an absent column.
  it('does not require an email', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    expect(bot.email).toBeNull()
  })
})

describe('the people list', () => {
  /**
   * The failure this prevents: enrolment is derived from whether a passkey ever
   * existed, so a bot would read as `enrolling` — rendered "Never signed in",
   * counted under "not fully set up", and sending an admin to chase something
   * that is working perfectly.
   */
  it('does not report a role identity as half set up', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    const { cookie } = await signedInAs('admin@example.test', 'admin')

    const body = (await (await app.request('/admin/people', { headers: { cookie } })).json()) as {
      people: Array<{ id: string; kind: string; enrolment: string }>
    }
    const row = body.people.find((person) => person.id === bot.id)

    expect(row?.kind).toBe('role')
    expect(row?.enrolment).toBe('not-applicable')
  })
})

describe('signing as a role, with no person in the flow', () => {
  it('exchanges a client secret for a token bound to the role', async () => {
    const { bot, credential } = await botWithCredential()

    const response = await tokenFor(credential.clientId, credential.secret)
    expect(response.status).toBe(200)

    const body = (await response.json()) as { pubkey: string; token_type: string }
    expect(body.token_type).toBe('Bearer')
    expect(body.pubkey).toBe(await getActivePubkey(bot.id))
  })

  it('and that token actually signs', async () => {
    const { bot, credential } = await botWithCredential([1])
    const token = (
      (await (await tokenFor(credential.clientId, credential.secret)).json()) as {
        access_token: string
      }
    ).access_token

    const signed = await app.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ event: { kind: 1, tags: [], content: 'from the bot' } }),
    })
    expect(signed.status).toBe(200)

    const body = (await signed.json()) as { event: { pubkey: string; sig: string } }
    expect(body.event.pubkey).toBe(await getActivePubkey(bot.id))
    expect(body.event.sig).toMatch(/^[0-9a-f]{128}$/)
  })

  it('refuses the wrong secret', async () => {
    const { credential } = await botWithCredential()
    expect((await tokenFor(credential.clientId, 'not-the-secret')).status).toBe(401)
  })

  // Every browser app is a public client and must stay one: a secret shipped in
  // a bundle is not a secret. So the grant has to be unusable for them however
  // plausible the client id looks.
  it('refuses a public client, which is every browser app', async () => {
    expect((await tokenFor('estiva-ship', 'anything-at-all')).status).toBe(401)
  })

  it('refuses an unknown client', async () => {
    expect((await tokenFor('no-such-bot', 'anything-at-all')).status).toBe(401)
  })

  /**
   * The secret buys a short token rather than being one, so disabling a bot
   * takes effect within the same TTL as offboarding a person — rather than
   * whenever somebody remembers to rotate a long-lived credential.
   */
  it('stops issuing once the identity is offboarded', async () => {
    const { bot, credential } = await botWithCredential()
    expect((await tokenFor(credential.clientId, credential.secret)).status).toBe(200)

    await setUserStatus(bot.id, 'offboarded')
    expect((await tokenFor(credential.clientId, credential.secret)).status).toBe(401)
  })

  it('rotating replaces the secret rather than adding a second', async () => {
    const { bot, credential } = await botWithCredential()
    const rotated = await issueServiceCredential({
      userId: bot.id,
      clientId: credential.clientId,
      name: 'Release Bot',
      allowedKinds: [1],
    })

    expect((await tokenFor(credential.clientId, credential.secret)).status).toBe(401)
    expect((await tokenFor(rotated.clientId, rotated.secret)).status).toBe(200)
  })
})

/**
 * PEEK-133: a bot that may sign kind:27235 and still cannot use it.
 *
 * `issueServiceCredential` wrote a hardcoded `'{}'` into `nip98_url_prefixes`,
 * so every runtime-minted credential was refused `nip98_url_not_allowed` for
 * every destination — and 27235 is the only kind a bot needs to read the relay
 * bridge at all, so this was the difference between a working agent and one
 * that cannot see anything.
 *
 * Seeded browser apps never hit it: `db/seed.ts` hands them the deployment's
 * own prefixes. Only credentials minted after boot were affected, which is why
 * a full green suite said nothing about it.
 *
 * The test environment allows `http://relay.test/` (src/test/setup.ts).
 */
describe('minting NIP-98 for the relay bridge', () => {
  const httpAuth = (url: string) => ({
    kind: 27235,
    tags: [
      ['u', url],
      ['method', 'POST'],
    ],
    content: '',
  })

  const sign = (token: string, event: unknown) =>
    app.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
      body: JSON.stringify({ event }),
    })

  const tokenValue = async (clientId: string, secret: string) =>
    ((await (await tokenFor(clientId, secret)).json()) as { access_token: string }).access_token

  async function relayReader(nip98UrlPrefixes: string[]) {
    const bot = await createRoleIdentity({ displayName: 'Relay Reader' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'relay-reader',
      name: 'Relay Reader',
      allowedKinds: [27235],
      nip98UrlPrefixes,
    })
    return { bot, credential, token: await tokenValue(credential.clientId, credential.secret) }
  }

  it('signs for a destination the credential was minted for', async () => {
    const { token } = await relayReader(['http://relay.test/'])
    expect((await sign(token, httpAuth('http://relay.test/query'))).status).toBe(200)
  })

  it('refuses when the credential carries no prefixes at all', async () => {
    const { token } = await relayReader([])
    const response = await sign(token, httpAuth('http://relay.test/query'))

    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'nip98_url_not_allowed' } },
    })
  })

  /**
   * The ordering that must survive: an app's list narrows within the
   * deployment's and can never widen it. Minting is not a way to grant
   * yourself a destination the deployment has not allowed.
   */
  it('refuses a destination the deployment forbids, however the credential was minted', async () => {
    const { token } = await relayReader(['https://evil.test/'])
    const response = await sign(token, httpAuth('https://evil.test/steal'))

    expect(response.status).toBe(422)
    await expect(response.json()).resolves.toMatchObject({
      error: { detail: { reason: 'nip98_url_not_allowed' } },
    })
  })

  /**
   * The half an insert-only fix would miss. Rotation is the common case —
   * re-issuing replaces the secret — so a conflict update that leaves
   * `nip98_url_prefixes` alone strands a bot on whatever it was created with.
   */
  it('applies new prefixes when an existing credential is re-issued', async () => {
    const { bot, credential, token: before } = await relayReader([])
    expect((await sign(before, httpAuth('http://relay.test/query'))).status).toBe(422)

    const rotated = await issueServiceCredential({
      userId: bot.id,
      clientId: credential.clientId,
      name: 'Relay Reader',
      allowedKinds: [27235],
      nip98UrlPrefixes: ['http://relay.test/'],
    })

    const token = await tokenValue(rotated.clientId, rotated.secret)
    expect((await sign(token, httpAuth('http://relay.test/query'))).status).toBe(200)
  })
})

describe('what a credential may not be issued for', () => {
  /**
   * The dangerous one. A credential that signs as a *person* is a way to act as
   * them without their passkey — precisely what every other path here exists to
   * prevent, and it would leave no trace distinguishable from their own use.
   */
  it('refuses to issue one for a human', async () => {
    const human = await createUserWithKey({ email: 'ada@example.test' })

    await expect(
      issueServiceCredential({
        userId: human.id,
        clientId: 'not-a-bot',
        name: 'Not A Bot',
        allowedKinds: [1],
      }),
    ).rejects.toThrow(/person, not a role/)
  })

  it('refuses an offboarded role', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    await setUserStatus(bot.id, 'offboarded')

    await expect(
      issueServiceCredential({
        userId: bot.id,
        clientId: 'release-bot',
        name: 'Release Bot',
        allowedKinds: [1],
      }),
    ).rejects.toThrow()
  })

  // The constraint exists in the schema too, so a credential cannot be given an
  // `acts_as` by hand without a secret — an app anybody could impersonate to
  // sign as the role.
  it('cannot act as an identity without a secret, even in SQL', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    await expect(
      query(
        `insert into app_credentials (client_id, name, allowed_kinds, acts_as_user_id)
         values ('sneaky', 'Sneaky', '{1}', $1)`,
        [bot.id],
      ),
    ).rejects.toThrow()
  })
})

describe('human paths refuse a role', () => {
  /**
   * A recovery link for a bot would enrol a passkey nobody asked for, handing
   * whoever opened it something that signs as the bot forever — and unlike a
   * person, there is nobody whose lockout would ever reveal it.
   */
  it('recovery refuses a role identity', async () => {
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    await expect(createRecovery({ userId: bot.id, createdBy: null })).rejects.toThrow(
      /no passkey to recover/,
    )
  })
})

describe('creating one through the console', () => {
  it('needs an admin', async () => {
    const { cookie } = await signedInAs('member@example.test', 'member')
    expect((await post('/admin/role-identities', { displayName: 'Bot' }, cookie)).status).toBe(403)
  })

  it('creates the identity and mints its credential, showing the secret once', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')

    const created = await post('/admin/role-identities', { displayName: 'Release Bot' }, cookie)
    expect(created.status).toBe(200)
    const { identity } = (await created.json()) as { identity: { id: string; pubkey: string } }

    const minted = await post(
      `/admin/role-identities/${identity.id}/credential`,
      { clientId: 'release-bot', name: 'Release Bot', allowedKinds: [1] },
      cookie,
    )
    expect(minted.status).toBe(200)
    const body = (await minted.json()) as { clientSecret: string }
    expect(body.clientSecret).toBeTruthy()

    // Usable immediately, which is the only way to know the mint was real.
    expect((await tokenFor('release-bot', body.clientSecret)).status).toBe(200)
  })

  it('never writes the secret to the audit log', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const created = await post('/admin/role-identities', { displayName: 'Release Bot' }, cookie)
    const { identity } = (await created.json()) as { identity: { id: string } }

    const minted = await post(
      `/admin/role-identities/${identity.id}/credential`,
      { clientId: 'release-bot', name: 'Release Bot', allowedKinds: [1] },
      cookie,
    )
    const { clientSecret } = (await minted.json()) as { clientSecret: string }

    const entries = await query<{ detail: Record<string, unknown> }>(
      "select detail from audit_events where action = 'role.credential'",
    )
    expect(entries.rows).toHaveLength(1)
    expect(JSON.stringify(entries.rows)).not.toContain(clientSecret)
  })

  /**
   * PEEK-134: an empty box must not mint a bot that cannot read.
   *
   * Empty is the right default for the *column* — fail closed — and the wrong
   * one for a *form*, because an admin who grants 27235 and says nothing about
   * destinations plainly means "the relay", not "nowhere". `db/seed.ts` already
   * resolves the same ambiguity the same way, so the route follows it.
   */
  async function mintedBot(cookie: string, body: Record<string, unknown>) {
    const created = await post('/admin/role-identities', { displayName: 'Relay Reader' }, cookie)
    const { identity } = (await created.json()) as { identity: { id: string } }
    const minted = await post(`/admin/role-identities/${identity.id}/credential`, body, cookie)
    return { minted, secret: ((await minted.json()) as { clientSecret: string }).clientSecret }
  }

  const signAs = async (clientId: string, secret: string, url: string) => {
    const { access_token } = (await (await tokenFor(clientId, secret)).json()) as {
      access_token: string
    }
    return app.request('/sign', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${access_token}` },
      body: JSON.stringify({
        event: {
          kind: 27235,
          tags: [
            ['u', url],
            ['method', 'POST'],
          ],
          content: '',
        },
      }),
    })
  }

  it('mints a bot that can reach the relay when no destination is given', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { secret } = await mintedBot(cookie, {
      clientId: 'relay-reader',
      name: 'Relay Reader',
      allowedKinds: [27235],
    })

    expect((await signAs('relay-reader', secret, 'http://relay.test/query')).status).toBe(200)
  })

  // The column is still a ceiling that can be lowered — the default exists to
  // stop an accident, not to make narrowing unavailable.
  it('honours an explicit narrower list', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    const { secret } = await mintedBot(cookie, {
      clientId: 'relay-reader',
      name: 'Relay Reader',
      allowedKinds: [27235],
      nip98UrlPrefixes: ['http://relay.test/events'],
    })

    expect((await signAs('relay-reader', secret, 'http://relay.test/events')).status).toBe(200)
    expect((await signAs('relay-reader', secret, 'http://relay.test/query')).status).toBe(422)
  })

  it('records what the credential can actually do, not what was asked for', async () => {
    const { cookie } = await signedInAs('admin@example.test', 'admin')
    await mintedBot(cookie, {
      clientId: 'relay-reader',
      name: 'Relay Reader',
      allowedKinds: [27235],
    })

    const entry = await queryOne<{ detail: { nip98UrlPrefixes: string[] } }>(
      "select detail from audit_events where action = 'role.credential'",
    )
    expect(entry?.detail.nip98UrlPrefixes).toEqual(['http://relay.test/'])
  })
})

/**
 * Renaming a role identity (PEEK-149).
 *
 * A bot cannot edit its own profile — no session, no passkey — so an admin
 * acting on it is the only way its name can ever change. Which mattered the
 * moment an agent started posting into team conversations: in a chat, a message
 * from "Claude" reads as a colleague and nothing says whose agent it is.
 */
describe('renaming a role identity', () => {
  it('renames it, and says whether the name reached the relay', async () => {
    const { cookie } = await signedInAs('admin@estiva.test', 'admin')
    const bot = await createRoleIdentity({ displayName: 'Claude' })

    const response = await patch(
      `/admin/role-identities/${bot.id}`,
      { displayName: 'Claude (steered by Miky)' },
      cookie,
    )
    expect(response.status).toBe(200)

    const body = (await response.json()) as {
      identity: { displayName: string }
      published: boolean
      publishError?: string | null
    }
    expect(body.identity.displayName).toBe('Claude (steered by Miky)')

    /*
      Asserted on the *reason*, not on the shape.

      The first version of this checked `typeof published === 'boolean'`, which
      a hardcoded `false` satisfies — proved by deleting the republish and
      watching the test still pass. Since the republish is the whole point of
      the endpoint (PEEK-165 was a name stored here and never sent to the
      relay), a check that survives its removal is decoration.

      `relay_not_configured` is `publishProfile`'s own first-line answer when
      there is no bridge, which there is not in a test. Only actually calling it
      produces that string. If this suite ever gains a relay, this becomes
      `published === true` rather than a looser assertion.
    */
    expect(body.published).toBe(false)
    expect(body.publishError).toBe('relay_not_configured')

    const row = await queryOne<{ display_name: string }>(
      'select display_name from users where id = $1',
      [bot.id],
    )
    expect(row?.display_name).toBe('Claude (steered by Miky)')
  })

  /*
    The property this endpoint exists to not violate. Renaming a person through
    an admin route would change how they appear in every app without their key
    — the thing every other path here is built to prevent — and would put a
    second writer on a profile PEEK-31 deliberately gave one.
  */
  it('refuses to rename a person', async () => {
    const { cookie } = await signedInAs('admin2@estiva.test', 'admin')
    const person = await createUserWithKey({ email: 'someone@estiva.test', role: 'member' })

    const response = await patch(
      `/admin/role-identities/${person.id}`,
      { displayName: 'Someone Else' },
      cookie,
    )
    expect(response.status).toBe(409)

    const row = await queryOne<{ display_name: string | null }>(
      'select display_name from users where id = $1',
      [person.id],
    )
    expect(row?.display_name ?? null).not.toBe('Someone Else')
  })

  it('refuses a member', async () => {
    const { cookie } = await signedInAs('member@estiva.test', 'member')
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })

    const response = await patch(
      `/admin/role-identities/${bot.id}`,
      { displayName: 'Nope' },
      cookie,
    )
    expect(response.status).toBe(403)
  })

  it('refuses an identity that does not exist', async () => {
    const { cookie } = await signedInAs('admin3@estiva.test', 'admin')
    const response = await patch(
      '/admin/role-identities/00000000-0000-0000-0000-000000000000',
      { displayName: 'Ghost' },
      cookie,
    )
    expect(response.status).toBe(404)
  })

  it('refuses an empty name', async () => {
    const { cookie } = await signedInAs('admin4@estiva.test', 'admin')
    const bot = await createRoleIdentity({ displayName: 'Release Bot' })
    const response = await patch(`/admin/role-identities/${bot.id}`, { displayName: '' }, cookie)
    expect(response.status).toBe(400)
  })
})

/**
 * Offboarding a person stops their bot (PEEK-164).
 *
 * This is the ticket's done-when and the reason ownership is recorded at all.
 * `offboardPerson` revoked passkeys, sessions, the handle and relay admission,
 * and never touched a credential — right while every role identity was the
 * workspace's, wrong the moment bots became personal. Production holds one
 * called "Claude (steered by Miky)"; offboarding Miky would have left it
 * reading and writing with a credential nobody revoked.
 *
 * Asserted through the **token grant**, not through a status column. A bot that
 * is marked offboarded and can still mint a token is not offboarded, and the
 * column is the mechanism rather than the property.
 */
describe('offboarding a person and their bots', () => {
  it('stops the bot minting tokens', async () => {
    const owner = await createUserWithKey({ email: 'owner@estiva.test', role: 'member' })
    const bot = await createRoleIdentity({ displayName: 'Their Bot', ownerUserId: owner.id })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'their-bot',
      name: 'Their Bot',
      allowedKinds: [27235],
    })

    // It works first, or the assertion below proves nothing.
    const before = await tokenFor(credential.clientId, credential.secret)
    expect(before.status).toBe(200)

    await offboardPerson(owner.id)

    const after = await tokenFor(credential.clientId, credential.secret)
    expect(after.status).toBe(401)
  })

  it('leaves a workspace-owned role alone', async () => {
    /*
      The other half of the distinction, and the one that would be catastrophic
      to get wrong: `Relay Operator` has no owner and must outlive everybody.
      A cascade that offboarded every role when anybody left would take relay
      admission for the whole workspace with it.
    */
    const leaver = await createUserWithKey({ email: 'leaver@estiva.test', role: 'member' })
    const orgBot = await createRoleIdentity({ displayName: 'Workspace Bot' })
    const credential = await issueServiceCredential({
      userId: orgBot.id,
      clientId: 'workspace-bot',
      name: 'Workspace Bot',
      allowedKinds: [27235],
    })

    await offboardPerson(leaver.id)

    const after = await tokenFor(credential.clientId, credential.secret)
    expect(after.status).toBe(200)
  })

  it('does not touch somebody else’s bot', async () => {
    const leaver = await createUserWithKey({ email: 'leaver2@estiva.test', role: 'member' })
    const other = await createUserWithKey({ email: 'other@estiva.test', role: 'member' })
    const theirBot = await createRoleIdentity({ displayName: 'Other Bot', ownerUserId: other.id })
    const credential = await issueServiceCredential({
      userId: theirBot.id,
      clientId: 'other-bot',
      name: 'Other Bot',
      allowedKinds: [27235],
    })

    await offboardPerson(leaver.id)

    const after = await tokenFor(credential.clientId, credential.secret)
    expect(after.status).toBe(200)
  })

  it('records which bots went with them, by name', async () => {
    const owner = await createUserWithKey({ email: 'owner2@estiva.test', role: 'member' })
    await createRoleIdentity({ displayName: 'Named Bot', ownerUserId: owner.id })

    await offboardPerson(owner.id)

    const audit = await queryOne<{ detail: { botsOffboarded?: string[] } }>(
      `select detail from audit_events
        where action = 'user.offboard' and detail->>'subjectUserId' = $1
        order by occurred_at desc limit 1`,
      [owner.id],
    )
    // Named rather than counted: "1 bot offboarded" is not checkable afterwards.
    expect(audit?.detail.botsOffboarded).toEqual(['Named Bot'])
  })

  /*
    An owner has to be a human, because the mechanism is offboarding and only a
    human gets offboarded. A bot owned by a bot would be unreachable by the
    thing meant to revoke it.
  */
  it('refuses a bot owned by another bot', async () => {
    const parent = await createRoleIdentity({ displayName: 'Parent Bot' })
    await expect(
      createRoleIdentity({ displayName: 'Child Bot', ownerUserId: parent.id }),
    ).rejects.toThrow()
  })
})

/**
 * Making a bot for yourself (PEEK-164).
 *
 * The bottleneck was real: onboarding one more person to the agent needed an
 * admin for three separate steps, and PEEK-163 existed only to make one of them
 * possible at all.
 *
 * What is asserted here is not that it works — it is the three properties that
 * make letting a non-admin do it safe, because each is one edit away from being
 * untrue and none of them fails loudly.
 */
describe('a person making their own bot', () => {
  const makeBot = (cookie: string, label: string) =>
    app.request('/me/bots', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label }),
    })

  it('needs no admin', async () => {
    const { cookie } = await signedInAs('selfserve@estiva.test', 'member')
    const response = await makeBot(cookie, 'Desktop')
    expect(response.status).toBe(200)

    const body = (await response.json()) as {
      clientId: string
      clientSecret: string
      bot: { displayName: string }
    }
    // Usable immediately: the secret is returned once and works.
    const token = await tokenFor(body.clientId, body.clientSecret)
    expect(token.status).toBe(200)
  })

  it('is read-only, whatever it asks for', async () => {
    const { cookie } = await signedInAs('readonly@estiva.test', 'member')
    const response = await makeBot(cookie, 'Reader')
    const body = (await response.json()) as { clientId: string; clientSecret: string }

    const token = await tokenFor(body.clientId, body.clientSecret)
    const issued = (await token.json()) as { allowed_kinds: number[] }
    /*
      27235 is NIP-98 HTTP auth and nothing else, so it can authenticate and
      read and cannot publish. This is what keeps "a bot may never exceed its
      owner" true by construction rather than by review — and asserting the
      exact list matters, since an extra kind here is an escalation any member
      could grant themselves.
    */
    expect(issued.allowed_kinds).toEqual([27235])
  })

  it('can actually mint NIP-98 for the relay, not merely hold the kind', async () => {
    const { cookie } = await signedInAs('destinations@estiva.test', 'member')
    const body = (await (await makeBot(cookie, 'Reader')).json()) as {
      clientId: string
      clientSecret: string
    }
    const issued = (await (await tokenFor(body.clientId, body.clientSecret)).json()) as {
      access_token: string
    }

    /*
      The hop every other assertion in this block stops one short of.

      `allowed_kinds: [27235]` above is necessary and not sufficient: NIP-98 is
      gated twice, once on the kind and again on the URL, ANDing the
      credential's `nip98_url_prefixes` against the deployment allowlist. A bot
      minted with an empty column passes the kind check and is then refused
      every destination there is — so it takes a token, reports success, and
      reads nothing.

      That is what the first self-service bot did on production: three green
      hops and `nip98_url_not_allowed` on the fourth. Asserting the token is
      200, as the tests above do, cannot see it — the token was always 200.
    */
    const signed = await app.request('/sign', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${issued.access_token}`,
      },
      body: JSON.stringify({
        event: {
          kind: 27235,
          tags: [
            ['u', 'http://relay.test/'],
            ['method', 'GET'],
          ],
          content: '',
        },
      }),
    })
    expect(signed.status).toBe(200)
  })

  it('cannot be given a name that hides whose it is', async () => {
    const { cookie } = await signedInAs('naming@estiva.test', 'member')
    const response = await makeBot(cookie, 'Support')
    const body = (await response.json()) as { bot: { displayName: string } }
    /*
      Composed rather than accepted. A message from a bot renders exactly like a
      colleague in a Peek conversation (PEEK-171), so a person naming their own
      "Support" is one careless moment from a chat nobody can attribute.
    */
    expect(body.bot.displayName).toContain('steered by')
    expect(body.bot.displayName).not.toBe('Support')
  })

  it('dies with its owner', async () => {
    const owner = await signedInAs('dies@estiva.test', 'member')
    const response = await makeBot(owner.cookie, 'Doomed')
    const body = (await response.json()) as { clientId: string; clientSecret: string }
    expect((await tokenFor(body.clientId, body.clientSecret)).status).toBe(200)

    await offboardPerson(owner.user.id)

    // The property that made self-service safe to offer at all.
    expect((await tokenFor(body.clientId, body.clientSecret)).status).toBe(401)
  })

  it('gives each one a distinct client id', async () => {
    const { cookie } = await signedInAs('distinct@estiva.test', 'member')
    const a = (await (await makeBot(cookie, 'Laptop')).json()) as { clientId: string }
    const b = (await (await makeBot(cookie, 'Laptop')).json()) as { clientId: string }
    // Same label twice is the ordinary case, and `client_id` is globally unique.
    expect(a.clientId).not.toBe(b.clientId)
  })

  it('stops at a limit rather than letting a loop make thousands', async () => {
    const { cookie } = await signedInAs('limit@estiva.test', 'member')
    for (let i = 0; i < MAX_BOTS_PER_PERSON; i++) {
      expect((await makeBot(cookie, `Bot ${i}`)).status).toBe(200)
    }
    const overflow = await makeBot(cookie, 'One too many')
    expect(overflow.status).toBe(409)
  })

  it('refuses somebody with no session', async () => {
    const response = await app.request('/me/bots', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ label: 'Nope' }),
    })
    expect(response.status).toBe(401)
  })
})

/**
 * Stopping one of your own bots (PEEK-164).
 *
 * `retire`, not `delete`: PEEK-170 was a Delete that removed a conversation
 * locally while every message in it stayed readable, so somebody believed a
 * thing was gone and it was not. What this produces is that the bot can never
 * mint another token; what it does not is remove anything the bot already
 * wrote.
 */
describe('stopping your own bot', () => {
  const makeBot = (cookie: string, label: string) =>
    app.request('/me/bots', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label }),
    })

  const stop = (cookie: string, id: string) =>
    app.request(`/me/bots/${id}`, { method: 'DELETE', headers: { cookie } })

  it('stops it minting tokens', async () => {
    const { cookie } = await signedInAs('retire@estiva.test', 'member')
    const created = (await (await makeBot(cookie, 'Doomed')).json()) as {
      bot: { userId: string }
      clientId: string
      clientSecret: string
    }
    expect((await tokenFor(created.clientId, created.clientSecret)).status).toBe(200)

    expect((await stop(cookie, created.bot.userId)).status).toBe(200)

    // The property, asserted through the grant rather than a status column.
    expect((await tokenFor(created.clientId, created.clientSecret)).status).toBe(401)
  })

  it('drops it from your list, so the limit frees up', async () => {
    const { cookie } = await signedInAs('freeup@estiva.test', 'member')
    const created = (await (await makeBot(cookie, 'Temp')).json()) as { bot: { userId: string } }

    await stop(cookie, created.bot.userId)

    const listed = (await (await app.request('/me/bots', { headers: { cookie } })).json()) as {
      bots: unknown[]
    }
    expect(listed.bots).toHaveLength(0)
  })

  /*
    The property this route must not lose. Anything else here is a convenience;
    this is the one that would let one member switch off another's tooling.
  */
  it('refuses somebody else’s bot', async () => {
    const owner = await signedInAs('mine@estiva.test', 'member')
    const stranger = await signedInAs('stranger@estiva.test', 'member')
    const created = (await (await makeBot(owner.cookie, 'Mine')).json()) as {
      bot: { userId: string }
      clientId: string
      clientSecret: string
    }

    // 404 rather than 403: somebody poking at ids should not learn which exist.
    expect((await stop(stranger.cookie, created.bot.userId)).status).toBe(404)

    // And it still works, which is the part that would actually hurt.
    expect((await tokenFor(created.clientId, created.clientSecret)).status).toBe(200)
  })

  it('refuses a workspace-owned role, even for an admin', async () => {
    const admin = await signedInAs('adminretire@estiva.test', 'admin')
    const orgBot = await createRoleIdentity({ displayName: 'Workspace Bot' })
    const credential = await issueServiceCredential({
      userId: orgBot.id,
      clientId: 'ws-bot-retire',
      name: 'Workspace Bot',
      allowedKinds: [27235],
    })

    /*
      This route is "your bots", and an unowned role is nobody's. Offboarding
      the relay operator through a self-service endpoint is exactly the shape of
      mistake that takes a workspace down.
    */
    expect((await stop(admin.cookie, orgBot.id)).status).toBe(404)
    expect((await tokenFor(credential.clientId, credential.secret)).status).toBe(200)
  })

  it('refuses without a session', async () => {
    const owner = await signedInAs('nosession@estiva.test', 'member')
    const created = (await (await makeBot(owner.cookie, 'Safe')).json()) as {
      bot: { userId: string }
    }
    const response = await app.request(`/me/bots/${created.bot.userId}`, { method: 'DELETE' })
    expect(response.status).toBe(401)
  })
})

/**
 * Widening a credential without rotating its secret.
 *
 * There was no way to do this: `issueServiceCredential` upserts
 * `client_secret_hash` alongside `allowed_kinds`, so a wider ceiling meant a
 * new secret and therefore a broken laptop, keychain and colleague. That
 * coupling is why `peek create-topic` shipped against a ceiling nobody wanted
 * to touch (PEEK-172).
 */
describe('changing what a credential may sign', () => {
  const setKinds = (cookie: string, clientId: string, allowedKinds: number[]) =>
    app.request(`/admin/credentials/${clientId}/kinds`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ allowedKinds }),
    })

  it('widens it and leaves the secret working', async () => {
    const { cookie } = await signedInAs('kinds@estiva.test', 'admin')
    const bot = await createRoleIdentity({ displayName: 'Widen Me' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'widen-me',
      name: 'Widen Me',
      allowedKinds: [27235],
    })

    expect((await setKinds(cookie, credential.clientId, [27235, 9007])).status).toBe(200)

    /*
      The whole point, asserted through the grant: the *same* secret still works
      and the token now reports the wider ceiling. A test that only checked the
      column would pass even if the secret had been replaced underneath.
    */
    const token = await tokenFor(credential.clientId, credential.secret)
    expect(token.status).toBe(200)
    const issued = (await token.json()) as { allowed_kinds: number[] }
    expect(issued.allowed_kinds).toEqual([27235, 9007])
  })

  it('can narrow as well as widen', async () => {
    const { cookie } = await signedInAs('narrow@estiva.test', 'admin')
    const bot = await createRoleIdentity({ displayName: 'Narrow Me' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'narrow-me',
      name: 'Narrow Me',
      allowedKinds: [27235, 9, 1851],
    })

    // Taking a capability back must be as easy as granting one, or the only
    // safe move after a mistake is rotating a secret somebody else is holding.
    await setKinds(cookie, credential.clientId, [27235])
    const issued = (await (await tokenFor(credential.clientId, credential.secret)).json()) as {
      allowed_kinds: number[]
    }
    expect(issued.allowed_kinds).toEqual([27235])
  })

  it('grants a credential one file type, and it saves that type and no other', async () => {
    // dce43a38: the agent credentials sit outside the seed, so 45010 and its
    // types reach them only through this route.
    const { cookie } = await signedInAs('types@estiva.test', 'admin')
    const bot = await createRoleIdentity({ displayName: 'Saves Projects' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'saves-projects',
      name: 'Saves Projects',
      allowedKinds: [27235],
    })
    const response = await app.request(`/admin/credentials/${credential.clientId}/kinds`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ allowedKinds: [27235, 45010], allowedTypes: ['osnova.project'] }),
    })
    expect(response.status).toBe(200)

    const { access_token, allowed_types } = (await (
      await tokenFor(credential.clientId, credential.secret)
    ).json()) as { access_token: string; allowed_types: string[] }
    // Answerable before the attempt, as allowed_kinds is (PEEK-172).
    expect(allowed_types).toEqual(['osnova.project'])
    const save = (type: string) =>
      app.request('/sign', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${access_token}` },
        body: JSON.stringify({ event: { kind: 45010, tags: [['type', type]], content: '' } }),
      })
    expect((await save('osnova.project')).status).toBe(200)
    const other = await save('leaf.document')
    expect(other.status).toBe(422)
    await expect(other.json()).resolves.toMatchObject({
      error: { code: 'policy_violation', detail: { reason: 'type_not_allowed' } },
    })
  })

  it('refuses a member', async () => {
    const { cookie } = await signedInAs('notadmin@estiva.test', 'member')
    const bot = await createRoleIdentity({ displayName: 'Not Yours' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'not-yours',
      name: 'Not Yours',
      allowedKinds: [27235],
    })

    /*
      The property that matters most here. PEEK-145 settled that there is no
      Folder boundary behind `allowed_kinds`, so this is the entire containment
      for an agent — a member who could widen their own bot could grant
      themselves the workspace.
    */
    expect((await setKinds(cookie, credential.clientId, [27235, 9, 1851])).status).toBe(403)

    const issued = (await (await tokenFor(credential.clientId, credential.secret)).json()) as {
      allowed_kinds: number[]
    }
    expect(issued.allowed_kinds).toEqual([27235])
  })

  it('refuses a credential that does not exist', async () => {
    const { cookie } = await signedInAs('missing@estiva.test', 'admin')
    expect((await setKinds(cookie, 'no-such-client', [27235])).status).toBe(404)
  })
})

/**
 * Seeing a client id, and replacing a secret without losing the bot.
 *
 * Found by reinstalling a Claude Desktop extension: it asks for the client id
 * and the secret again, and the console showed neither. The client id is not a
 * secret and was hidden anyway; the secret genuinely cannot be shown, which
 * left "make another bot and stop this one" as the only recovery — and that
 * costs a pubkey, a relay admission, a name and every message the old bot
 * wrote.
 */
describe('recovering a bot you can no longer configure', () => {
  const makeBot = (cookie: string, label: string) =>
    app.request('/me/bots', {
      method: 'POST',
      headers: { 'content-type': 'application/json', cookie },
      body: JSON.stringify({ label }),
    })

  it('lists the client id, which is not a secret', async () => {
    const { cookie } = await signedInAs('seeid@estiva.test', 'member')
    const created = (await (await makeBot(cookie, 'Laptop')).json()) as { clientId: string }

    const listed = (await (await app.request('/me/bots', { headers: { cookie } })).json()) as {
      bots: { clientId: string | null }[]
    }
    expect(listed.bots[0]?.clientId).toBe(created.clientId)
  })

  it('never lists the secret', async () => {
    const { cookie } = await signedInAs('nosecret@estiva.test', 'member')
    const created = (await (await makeBot(cookie, 'Laptop')).json()) as { clientSecret: string }

    const body = await (await app.request('/me/bots', { headers: { cookie } })).text()
    /*
      The property that must never regress. Only a SHA-256 is stored, so this
      cannot leak by accident today — but a future "convenience" that kept the
      plaintext would make this listing the place it escapes from.
    */
    expect(body).not.toContain(created.clientSecret)
  })

  it('gives a new secret and keeps the identity', async () => {
    const { cookie } = await signedInAs('rotate@estiva.test', 'member')
    const created = (await (await makeBot(cookie, 'Laptop')).json()) as {
      bot: { userId: string; pubkey: string | null }
      clientId: string
      clientSecret: string
    }

    const rotated = (await (
      await app.request(`/me/bots/${created.bot.userId}/secret`, {
        method: 'POST',
        headers: { cookie },
      })
    ).json()) as { clientId: string; clientSecret: string }

    // Same identity, different secret — that is the whole point of rotating
    // rather than replacing: the pubkey and its relay admission survive.
    expect(rotated.clientId).toBe(created.clientId)
    expect(rotated.clientSecret).not.toBe(created.clientSecret)

    expect((await tokenFor(rotated.clientId, rotated.clientSecret)).status).toBe(200)
    // And the old one is dead, which is the point when the reason to rotate is
    // that somebody else may be holding it.
    expect((await tokenFor(created.clientId, created.clientSecret)).status).toBe(401)
  })

  it('carries the ceiling over rather than resetting it', async () => {
    const { cookie } = await signedInAs('keepkinds@estiva.test', 'member')
    const created = (await (await makeBot(cookie, 'Laptop')).json()) as {
      bot: { userId: string }
      clientId: string
    }

    const rotated = (await (
      await app.request(`/me/bots/${created.bot.userId}/secret`, {
        method: 'POST',
        headers: { cookie },
      })
    ).json()) as { clientId: string; clientSecret: string }

    /*
      Restating a ceiling from memory is how one gets silently narrowed — the
      failure `/sign` later reports as `kind_not_allowed` on something that
      worked yesterday (PEEK-172). Rotation reads it rather than asking.
    */
    const issued = (await (await tokenFor(rotated.clientId, rotated.clientSecret)).json()) as {
      allowed_kinds: number[]
    }
    expect(issued.allowed_kinds).toEqual([27235])
  })

  it('refuses to rotate somebody else’s bot', async () => {
    const owner = await signedInAs('mineonly@estiva.test', 'member')
    const stranger = await signedInAs('notmine@estiva.test', 'member')
    const created = (await (await makeBot(owner.cookie, 'Mine')).json()) as {
      bot: { userId: string }
      clientId: string
      clientSecret: string
    }

    const response = await app.request(`/me/bots/${created.bot.userId}/secret`, {
      method: 'POST',
      headers: { cookie: stranger.cookie },
    })
    expect(response.status).toBe(404)
    // And rotating did not happen, which is the half that would actually hurt.
    expect((await tokenFor(created.clientId, created.clientSecret)).status).toBe(200)
  })
})
