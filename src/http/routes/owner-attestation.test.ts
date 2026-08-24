/**
 * The NIP-OA attestation the client-credentials grant hands out.
 *
 * "Claude (steered by Miky)" is a display name, and a display name proves
 * nothing: `kind:0` is self-published, so any admitted key can claim to be
 * steered by anybody. This is the unforgeable version — the owner's key signing
 * a statement naming the bot's key, which Buzz verifies with no trust in this
 * service and records in `users.agent_owner_pubkey`.
 *
 * These tests assert the *cryptographic* content, not the shape. An earlier
 * habit in this codebase was checking `typeof x === 'boolean'` for exactly the
 * thing under test, which passes while the behaviour is absent; here the
 * question is always "does this signature verify, and whom does it name".
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { closePool } from '../../db/pool.js'
import { ownerAttestation } from '../../domain/attestation.js'
import { getActivePubkey } from '../../domain/keys.js'
import { offboardPerson } from '../../domain/offboarding.js'
import { createRoleIdentity, issueServiceCredential } from '../../domain/roles.js'
import { createUserWithKey, setUserStatus } from '../../domain/users.js'
import { verifyAuthTag } from '../../nostr/nip-oa.js'
import { prepareDatabase, truncateAll } from '../../test/db.js'
import { createApp } from '../app.js'

const app = createApp()

const tokenFor = (clientId: string, clientSecret: string) =>
  app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ grantType: 'client_credentials', clientId, clientSecret }),
  })

interface IssuedToken {
  pubkey: string
  allowed_kinds: number[]
  owner_attestation?: [string, string, string, string]
}

/** A person, a bot they own, and a credential for it — the production shape. */
async function ownedBot(email: string, clientId: string) {
  const owner = await createUserWithKey({ displayName: 'Miky', email, kind: 'human' })
  const bot = await createRoleIdentity({
    displayName: 'Claude (steered by Miky)',
    ownerUserId: owner.id,
  })
  const credential = await issueServiceCredential({
    userId: bot.id,
    clientId,
    name: 'Claude',
    allowedKinds: [27235, 9],
  })
  return { owner, bot, credential }
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

describe('a bot that belongs to somebody', () => {
  it('is handed an attestation its owner signed', async () => {
    const { owner, credential } = await ownedBot('owned@estiva.test', 'claude-owned')

    const issued = (await (
      await tokenFor(credential.clientId, credential.secret)
    ).json()) as IssuedToken
    expect(issued.owner_attestation).toBeDefined()

    /*
      The load-bearing assertion. `verifyAuthTag` recomputes the preimage from
      the *bot's* pubkey and checks the Schnorr signature, so this passes only
      if the tag names this bot and was signed by this owner's key. Comparing
      `owner_attestation[1]` to the owner pubkey alone would pass on an
      unsigned tag with the right string in slot 1.
    */
    const ownerPubkey = await getActivePubkey(owner.id)
    expect(verifyAuthTag(issued.owner_attestation, issued.pubkey)).toBe(ownerPubkey)
  })

  it('does not attest the bot to itself', async () => {
    const { credential } = await ownedBot('self@estiva.test', 'claude-self')
    const issued = (await (
      await tokenFor(credential.clientId, credential.secret)
    ).json()) as IssuedToken
    // The relay rejects owner == agent outright, so an attestation naming the
    // bot as its own owner would be worse than none: it would look wired up.
    expect(issued.owner_attestation).toBeDefined()
    expect(issued.owner_attestation?.[1]).not.toBe(issued.pubkey)
  })

  it('binds the attestation to this bot and no other', async () => {
    const first = await ownedBot('one@estiva.test', 'claude-one')
    const second = await ownedBot('two@estiva.test', 'claude-two')

    const a = (await (
      await tokenFor(first.credential.clientId, first.credential.secret)
    ).json()) as IssuedToken
    const b = (await (
      await tokenFor(second.credential.clientId, second.credential.secret)
    ).json()) as IssuedToken

    // Each must have got one, or the cross-check below throws for the boring
    // reason that there is nothing to check.
    expect(a.owner_attestation).toBeDefined()
    expect(b.owner_attestation).toBeDefined()
    expect(verifyAuthTag(a.owner_attestation, a.pubkey)).toBeTypeOf('string')

    // Lifting one bot's attestation onto another's key must not verify — the
    // agent pubkey is inside the signed preimage, which is what stops an agent
    // borrowing a colleague's ownership claim.
    expect(() => verifyAuthTag(a.owner_attestation, b.pubkey)).toThrow(/verification failed/)
  })

  it('uses empty conditions, so it constrains nothing', async () => {
    const { credential } = await ownedBot('cond@estiva.test', 'claude-cond')
    const issued = (await (
      await tokenFor(credential.clientId, credential.secret)
    ).json()) as IssuedToken
    // The relationship recorded is "who steers this agent". It does not vary by
    // kind, and Buzz never re-reads the conditions after verifying.
    expect(issued.owner_attestation).toBeDefined()
    expect(issued.owner_attestation?.[2]).toBe('')
  })
})

describe('a bot that belongs to the workspace', () => {
  it('gets a token with no attestation at all', async () => {
    const bot = await createRoleIdentity({ displayName: 'Relay Operator' })
    const credential = await issueServiceCredential({
      userId: bot.id,
      clientId: 'relay-operator',
      name: 'Relay Operator',
      allowedKinds: [27235],
    })

    const response = await tokenFor(credential.clientId, credential.secret)
    expect(response.status).toBe(200)
    const issued = (await response.json()) as IssuedToken
    // Absent, not null and not an empty array: there is no owner, and saying so
    // by omission is what lets an agent tell "no owner" from "older service".
    expect(issued).not.toHaveProperty('owner_attestation')
    expect(issued.allowed_kinds).toEqual([27235])
  })
})

describe('when the owner is no longer active', () => {
  /**
   * Checked against the domain function directly, because the grant is not the
   * place this shows up: offboarding cascades to the bot's credential, so
   * `/token` refuses before it ever reaches the attestation. That refusal is a
   * different mechanism (PEEK-164's first half) and it would hide whether this
   * one works.
   *
   * `suspended` is the state that proves the point — the credential still
   * authenticates, so a missing status check here would attest a person who has
   * had their access withdrawn.
   */
  it('does not attest a suspended owner', async () => {
    const { owner, bot } = await ownedBot('suspended@estiva.test', 'claude-suspended')

    // Before, so the assertion after cannot pass for want of an owner.
    expect(await ownerAttestation(bot.id)).toBeDefined()

    await setUserStatus(owner.id, 'suspended')

    expect(await ownerAttestation(bot.id)).toBeUndefined()
  })

  it('does not attest an offboarded owner', async () => {
    const { owner, bot } = await ownedBot('leaver@estiva.test', 'claude-leaver')
    expect(await ownerAttestation(bot.id)).toBeDefined()

    await offboardPerson(owner.id)

    expect(await ownerAttestation(bot.id)).toBeUndefined()
  })

  it('still issues a token to a bot it cannot attest', async () => {
    const { owner, credential, bot } = await ownedBot('token@estiva.test', 'claude-token')
    await setUserStatus(owner.id, 'suspended')
    expect(await ownerAttestation(bot.id)).toBeUndefined()

    /*
      The trade this feature makes. An attestation is an enhancement to a token
      that worked without one for a year: a bot that cannot be attributed is a
      worse bot, a bot that cannot get a token is a broken one.
    */
    const response = await tokenFor(credential.clientId, credential.secret)
    expect(response.status).toBe(200)
    const issued = (await response.json()) as IssuedToken
    expect(issued).not.toHaveProperty('owner_attestation')
    expect(issued.allowed_kinds).toEqual([27235, 9])
  })
})
