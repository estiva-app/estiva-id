/**
 * PEEK-71 rules, as pure functions.
 *
 * The DB-backed path is covered in `src/http/routes/sign.test.ts`; these are the
 * rules themselves, where every branch is cheap to state.
 */
import { describe, expect, it } from 'vitest'
import type { UnsignedEvent } from '../nostr/event.js'
import { type AppPolicy, evaluateSignPolicy } from './policy.js'

const RELAY = 'https://relay.estiva.test/'

// The lists PEEK-71 gives, which are knowable from what each app publishes.
const PEEK: AppPolicy = {
  clientId: 'estiva-peek',
  name: 'Estiva Peek',
  allowedKinds: [9, 7, 5, 9007],
  nip98UrlPrefixes: [RELAY],
  status: 'active',
}

const SHIP: AppPolicy = {
  clientId: 'estiva-ship',
  name: 'estiva-ship',
  allowedKinds: [30850, 30851, 1851, 9, 5, 31989],
  nip98UrlPrefixes: [],
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
