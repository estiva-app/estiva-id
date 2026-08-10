/**
 * The seeded signing policies, as shipped (PEEK-71).
 *
 * `policy.test.ts` covers the *rules* against hand-written fixtures. This covers
 * the **lists themselves**, which is where the gap was: every rule behaved
 * correctly and Ship still could not create a project, because the list it was
 * given was missing a kind. A policy that is enforced perfectly and specified
 * wrongly fails exactly like a bug.
 */
import { describe, expect, it } from 'vitest'
import { SEED_APPS } from './seed.js'

const app = (clientId: string) => {
  const found = SEED_APPS.find((a) => a.clientId === clientId)
  if (!found) throw new Error(`no seeded app ${clientId}`)
  return found
}

/** Ship's kinds, from `estiva-ship/src/kinds.ts`. */
const SHIP = {
  FOLDER: 9007,
  PROJECT: 30850,
  ISSUE: 30851,
  CHANGE: 1851,
  MESSAGE: 9,
} as const

/** Both names Ship may present while PEEK-98's rename is in flight. */
const SHIP_CLIENT_IDS = ['estiva-ship', 'linear-lite'] as const

describe('seeded signing policies', () => {
  it.each(SHIP_CLIENT_IDS)('lets %s sign the Folder every object requires', (clientId) => {
    // The regression: `createProject` publishes the Folder *before* the
    // Project, so without this Ship cannot create its first container — only
    // add to one somebody else made. Listing object kinds without their
    // container is a broken ceiling, not a lower one.
    expect(app(clientId).allowedKinds).toContain(SHIP.FOLDER)
  })

  it.each(SHIP_CLIENT_IDS)('lets %s sign every object kind Ship publishes', (clientId) => {
    const allowed = app(clientId).allowedKinds
    for (const kind of [SHIP.PROJECT, SHIP.ISSUE, SHIP.CHANGE, SHIP.MESSAGE]) {
      expect(allowed).toContain(kind)
    }
  })

  it('gives Ship the same policy under both names', () => {
    // The failure this catches is nastier than a missing kind: an app that can
    // sign under one of its names and not the other looks like an intermittent
    // bug rather than a config difference (PEEK-98).
    const [next, old] = SHIP_CLIENT_IDS.map(app)
    expect(next?.allowedKinds).toEqual(old?.allowedKinds)
    expect(next?.nip98UrlPrefixes).toEqual(old?.nip98UrlPrefixes)
    expect(next?.redirectUris()).toEqual(old?.redirectUris())
  })

  it('gives every app NIP-98, without which it cannot reach the bridge at all', () => {
    // A signed event an app cannot publish is a rubber stamp with no door.
    for (const seeded of SEED_APPS) {
      expect(seeded.allowedKinds).toContain(27235)
    }
  })

  it('grants no app kind:0, which the identity service alone publishes', () => {
    for (const seeded of SEED_APPS) {
      expect(seeded.allowedKinds).not.toContain(0)
    }
  })
})
