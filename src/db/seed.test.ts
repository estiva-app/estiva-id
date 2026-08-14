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

describe('seeded signing policies', () => {
  it('lets Ship sign the Folder every object requires', () => {
    // The regression: `createProject` publishes the Folder *before* the
    // Project, so without this Ship cannot create its first container — only
    // add to one somebody else made. Listing object kinds without their
    // container is a broken ceiling, not a lower one.
    expect(app('estiva-ship').allowedKinds).toContain(SHIP.FOLDER)
  })

  it('lets Ship sign every object kind it publishes', () => {
    const allowed = app('estiva-ship').allowedKinds
    for (const kind of [SHIP.PROJECT, SHIP.ISSUE, SHIP.CHANGE, SHIP.MESSAGE]) {
      expect(allowed).toContain(kind)
    }
  })

  it('lets Peek sign the Change kind it needs to act on a Ship object', () => {
    // Acting on another app's object means writing *that app's* kind: Peek's
    // `buildActionEvent` takes it from the target's own manifest, so changing a
    // Ship project's status from Peek is necessarily a kind:1851. Without it
    // `/sign` refuses with `kind_not_allowed` at the last step, after the
    // manifest has already agreed the action is offered — which is exactly how
    // it failed in the demo.
    expect(app('estiva-peek').allowedKinds).toContain(SHIP.CHANGE)
  })

  it('no longer seeds the retired linear-lite credential', () => {
    // Phase 3 of PEEK-98. Leaving it here would mean the next re-seed
    // recreating the row somebody deleted on the box.
    expect(SEED_APPS.map((seeded) => seeded.clientId)).not.toContain('linear-lite')
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
