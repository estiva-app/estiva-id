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
import { createRecovery } from '../../domain/recovery.js'
import { createRoleIdentity, issueServiceCredential } from '../../domain/roles.js'
import { createSession } from '../../domain/sessions.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
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
  post('/token', { grantType: 'client_credentials', clientId, clientSecret })

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
