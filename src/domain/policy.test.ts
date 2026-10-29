/**
 * PEEK-71 rules, as pure functions.
 *
 * The DB-backed path is covered in `src/http/routes/sign.test.ts`; these are the
 * rules themselves, where every branch is cheap to state.
 */
import { describe, expect, it } from 'vitest'
import type { UnsignedEvent } from '../nostr/event.js'
import { type AppPolicy, evaluateEncryptionPolicy, evaluateSignPolicy } from './policy.js'

const RELAY = 'https://relay.estiva.test/'
const RELAY_WS = 'wss://relay.estiva.test'

// The lists PEEK-71 gives, which are knowable from what each app publishes.
const PEEK: AppPolicy = {
  clientId: 'estiva-peek',
  name: 'Estiva Peek',
  allowedKinds: [9, 7, 5, 9007],
  allowedTypes: [],
  nip98UrlPrefixes: [RELAY],
  relayAuthUrls: [],
  status: 'active',
}

const SHIP: AppPolicy = {
  clientId: 'estiva-ship',
  name: 'estiva-ship',
  allowedKinds: [30850, 30851, 1851, 9, 5, 31989],
  allowedTypes: [],
  nip98UrlPrefixes: [],
  relayAuthUrls: [],
  status: 'active',
}

function event(kind: number, tags: string[][] = []): UnsignedEvent {
  return { pubkey: 'a'.repeat(64), created_at: 1_753_300_200, kind, tags, content: '' }
}

describe('kind allowlists', () => {
  it('allows the kinds an app actually publishes', () => {
    for (const kind of PEEK.allowedKinds) {
      expect(evaluateSignPolicy(event(kind), PEEK, [RELAY]).allowed).toBe(true)
    }
    for (const kind of SHIP.allowedKinds) {
      expect(evaluateSignPolicy(event(kind), SHIP, [RELAY]).allowed).toBe(true)
    }
  })

  it('refuses a kind outside the app’s list', () => {
    // 30850 is Linear-lite's, not Peek's. Apps do not inherit each other's.
    expect(evaluateSignPolicy(event(30850), PEEK, [RELAY])).toMatchObject({
      allowed: false,
      reason: 'kind_not_allowed',
    })
  })

  it('refuses everything from a disabled app', () => {
    expect(evaluateSignPolicy(event(9), { ...PEEK, status: 'disabled' }, [RELAY])).toMatchObject({
      allowed: false,
      reason: 'app_disabled',
    })
  })
})

describe('a file save (45010) is limited by its type', () => {
  const LEAF: AppPolicy = { ...SHIP, clientId: 'estiva-leaf', allowedKinds: [45010] }
  const save = (type?: string) => event(45010, type ? [['type', type]] : [])

  it('signs a type on the app’s list', () => {
    const app = { ...LEAF, allowedTypes: ['osnova.project'] }
    expect(evaluateSignPolicy(save('osnova.project'), app, [RELAY]).allowed).toBe(true)
  })

  it('refuses a type off the list, a save with no type, and every type when the list is empty', () => {
    const app = { ...LEAF, allowedTypes: ['osnova.project'] }
    for (const [policy, unsigned] of [
      [app, save('leaf.document')],
      [app, save()],
      [LEAF, save('osnova.project')],
    ] as const) {
      expect(evaluateSignPolicy(unsigned, policy, [RELAY])).toMatchObject({
        allowed: false,
        reason: 'type_not_allowed',
      })
    }
  })
})

describe('kind:0 is never signable through /sign', () => {
  it('refuses kind:0 for every app', () => {
    for (const app of [PEEK, SHIP]) {
      expect(evaluateSignPolicy(event(0), app, [RELAY])).toMatchObject({
        allowed: false,
        reason: 'kind_profile_forbidden',
      })
    }
  })

  // The rule has to survive the row being edited, because the row is exactly
  // what an attacker with database access would edit.
  it('refuses kind:0 even when the app row explicitly allows it', () => {
    const overreaching: AppPolicy = { ...PEEK, allowedKinds: [0, 9] }
    expect(evaluateSignPolicy(event(0), overreaching, [RELAY])).toMatchObject({
      allowed: false,
      reason: 'kind_profile_forbidden',
    })
  })
})

describe('NIP-98 (27235) is constrained by URL', () => {
  const httpAuth = (url?: string) =>
    event(
      27235,
      url
        ? [
            ['u', url],
            ['method', 'POST'],
          ]
        : [['method', 'POST']],
    )

  const peekWith98: AppPolicy = { ...PEEK, allowedKinds: [...PEEK.allowedKinds, 27235] }

  it('allows an allowlisted relay bridge URL', () => {
    const decision = evaluateSignPolicy(httpAuth(`${RELAY}query`), peekWith98, [RELAY])
    expect(decision.allowed).toBe(true)
  })

  it('refuses an arbitrary destination', () => {
    expect(
      evaluateSignPolicy(httpAuth('https://evil.test/steal'), peekWith98, [RELAY]),
    ).toMatchObject({ allowed: false, reason: 'nip98_url_not_allowed' })
  })

  it('refuses a 27235 event with no u tag', () => {
    expect(evaluateSignPolicy(httpAuth(), peekWith98, [RELAY])).toMatchObject({
      allowed: false,
      reason: 'nip98_missing_url',
    })
  })

  // Fail-closed while PEEK-33 is open: the relay bridge host is not decided, so
  // an empty deployment allowlist must mean "mint nothing".
  it('refuses everything when the deployment allowlist is empty', () => {
    expect(evaluateSignPolicy(httpAuth(`${RELAY}query`), peekWith98, [])).toMatchObject({
      allowed: false,
      reason: 'nip98_url_not_allowed',
    })
  })

  it('refuses when the app has no prefixes, even if the deployment allows the URL', () => {
    const noPrefixes: AppPolicy = { ...peekWith98, nip98UrlPrefixes: [] }
    expect(evaluateSignPolicy(httpAuth(`${RELAY}query`), noPrefixes, [RELAY])).toMatchObject({
      allowed: false,
      reason: 'nip98_url_not_allowed',
    })
  })

  // An app cannot widen the deployment bound by listing a URL outside it.
  it('does not let an app grant itself a destination the deployment forbids', () => {
    const overreaching: AppPolicy = {
      ...peekWith98,
      nip98UrlPrefixes: ['https://evil.test/'],
    }
    expect(
      evaluateSignPolicy(httpAuth('https://evil.test/steal'), overreaching, [RELAY]),
    ).toMatchObject({ allowed: false, reason: 'nip98_url_not_allowed' })
  })
})

describe('NIP-42 (22242) is constrained by relay', () => {
  const relayAuth = (relay?: string) =>
    event(
      22242,
      relay
        ? [
            ['relay', relay],
            ['challenge', 'abc123'],
          ]
        : [['challenge', 'abc123']],
    )

  /** The paired shape PEE-4 requires: the kind and a relay, never one alone. */
  const peekWith42: AppPolicy = {
    ...PEEK,
    allowedKinds: [...PEEK.allowedKinds, 22242],
    relayAuthUrls: [RELAY_WS],
  }

  it('allows a challenge from the deployment’s own relay', () => {
    expect(evaluateSignPolicy(relayAuth(RELAY_WS), peekWith42, [RELAY], [RELAY_WS]).allowed).toBe(
      true,
    )
  })

  it('refuses a challenge from any other relay', () => {
    // The whole reason the grant could not ship alone: answering this proves to
    // evil.test that the user is present there.
    expect(
      evaluateSignPolicy(relayAuth('wss://evil.test'), peekWith42, [RELAY], [RELAY_WS]),
    ).toMatchObject({ allowed: false, reason: 'relay_auth_relay_not_allowed' })
  })

  it('refuses a 22242 with no relay tag', () => {
    expect(evaluateSignPolicy(relayAuth(), peekWith42, [RELAY], [RELAY_WS])).toMatchObject({
      allowed: false,
      reason: 'relay_auth_missing_relay',
    })
  })

  it('refuses a relay tag that is not a URL at all', () => {
    expect(
      evaluateSignPolicy(relayAuth('not-a-url'), peekWith42, [RELAY], [RELAY_WS]),
    ).toMatchObject({ allowed: false, reason: 'relay_auth_missing_relay' })
  })

  // Fail-closed, like the NIP-98 bound above: a deployment that has not named
  // its relays answers no challenges.
  it('refuses everything when the deployment allowlist is empty', () => {
    expect(evaluateSignPolicy(relayAuth(RELAY_WS), peekWith42, [RELAY], [])).toMatchObject({
      allowed: false,
      reason: 'relay_auth_relay_not_allowed',
    })
  })

  // ...including when the argument is simply not passed. The default exists so
  // that a caller which forgets the bound refuses rather than grants.
  it('refuses when the deployment bound is omitted entirely', () => {
    expect(evaluateSignPolicy(relayAuth(RELAY_WS), peekWith42, [RELAY])).toMatchObject({
      allowed: false,
      reason: 'relay_auth_relay_not_allowed',
    })
  })

  it('refuses when the app has no relays, even if the deployment allows one', () => {
    // This is the state a bare `22242` in seed.ts would produce, and the reason
    // the grant and the scope land together: the row decides, not the kind list.
    const unscoped: AppPolicy = { ...peekWith42, relayAuthUrls: [] }
    expect(evaluateSignPolicy(relayAuth(RELAY_WS), unscoped, [RELAY], [RELAY_WS])).toMatchObject({
      allowed: false,
      reason: 'relay_auth_relay_not_allowed',
    })
  })

  it('does not let an app grant itself a relay the deployment forbids', () => {
    const overreaching: AppPolicy = { ...peekWith42, relayAuthUrls: ['wss://evil.test'] }
    expect(
      evaluateSignPolicy(relayAuth('wss://evil.test'), overreaching, [RELAY], [RELAY_WS]),
    ).toMatchObject({ allowed: false, reason: 'relay_auth_relay_not_allowed' })
  })

  it('treats a trailing slash as the same relay on either side', () => {
    // `wss://x` and `wss://x/` are one relay and both are written in practice.
    for (const [configured, tagged] of [
      [RELAY_WS, `${RELAY_WS}/`],
      [`${RELAY_WS}/`, RELAY_WS],
      ['wss://RELAY.estiva.TEST/', RELAY_WS],
    ] as const) {
      const app: AppPolicy = { ...peekWith42, relayAuthUrls: [configured] }
      expect(
        evaluateSignPolicy(relayAuth(tagged), app, [RELAY], [configured]).allowed,
        `${configured} vs ${tagged}`,
      ).toBe(true)
    }
  })

  // The reason this branch matches exactly where NIP-98 matches by prefix. As a
  // prefix, a bare origin also admits every host that merely starts with it.
  it('does not admit a lookalike host that extends the allowed one', () => {
    for (const impostor of [
      'wss://relay.estiva.test.attacker.example/',
      'wss://relay.estiva.test.attacker.example',
      'wss://relay.estiva.testing/',
    ]) {
      expect(
        evaluateSignPolicy(relayAuth(impostor), peekWith42, [RELAY], [RELAY_WS]),
        impostor,
      ).toMatchObject({ allowed: false, reason: 'relay_auth_relay_not_allowed' })
    }
  })

  it('still refuses 22242 outright for an app that was never granted the kind', () => {
    // The kind check runs first, so an app without 22242 never reaches the
    // relay branch — and gets the refusal that names the real reason.
    expect(evaluateSignPolicy(relayAuth(RELAY_WS), PEEK, [RELAY], [RELAY_WS])).toMatchObject({
      allowed: false,
      reason: 'kind_not_allowed',
    })
  })

  it('refuses a disabled app before it looks at the relay', () => {
    expect(
      evaluateSignPolicy(
        relayAuth(RELAY_WS),
        { ...peekWith42, status: 'disabled' },
        [RELAY],
        [RELAY_WS],
      ),
    ).toMatchObject({ allowed: false, reason: 'app_disabled' })
  })
})

describe('the encryption gate (CRO-1)', () => {
  it('lets an active app encrypt', () => {
    expect(evaluateEncryptionPolicy(PEEK).allowed).toBe(true)
  })

  it('refuses a disabled app', () => {
    // `/nip44/decrypt` reads what somebody has read and when. A credential that
    // has been turned off must not still resolve that.
    expect(evaluateEncryptionPolicy({ ...PEEK, status: 'disabled' })).toMatchObject({
      allowed: false,
      reason: 'app_disabled',
    })
  })

  it('does not consult the kind list, which says nothing about encryption', () => {
    // A kind ceiling bounds what an app may *publish*. Encryption publishes
    // nothing, so an app with an empty list is still allowed here — stated as a
    // test because reading `allowedKinds` would be the natural wrong instinct.
    expect(evaluateEncryptionPolicy({ ...PEEK, allowedKinds: [] }).allowed).toBe(true)
  })
})
