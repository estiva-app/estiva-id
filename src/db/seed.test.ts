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
import { config } from '../config.js'
import { SEED_APPS } from './seed.js'

const app = (clientId: string) => {
  const found = SEED_APPS.find((a) => a.clientId === clientId)
  if (!found) throw new Error(`no seeded app ${clientId}`)
  return found
}

/** Peek's own kinds, from `peek-app/convex/nostr/events.ts`. */
const PEEK = {
  ASSERTION: 9101,
  EDIT_CHANNEL_METADATA: 9002,
  DELETE_GROUP: 9008,
} as const

/** Ship's kinds, from `estiva-ship/src/kinds.ts`. */
const SHIP = {
  FOLDER: 9007,
  PROJECT: 30850,
  ISSUE: 30851,
  CHANGE: 1851,
  MESSAGE: 9,
  COMMENT: 1111,
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

  it('lets both apps sign the NIP-22 comment kind', () => {
    // Granted before anything writes it, which is the unusual part and the
    // point. Ship's comments are moving from kind:9 to `1111` (REW-10); its
    // fold already reads both and the relay already accepts both, so this
    // ceiling is the last thing that would refuse — and it refuses at the final
    // publish, long after the code looks finished.
    //
    // Peek is here for a reason that is a step removed: it never chooses a
    // comment kind, it stamps whatever the owning app's manifest declares. So
    // Ship flipping its manifest changes what *Peek* signs, with no change to
    // Peek. Granting one without the other breaks the other app.
    for (const client of ['estiva-ship', 'estiva-peek']) {
      expect(app(client).allowedKinds).toContain(SHIP.COMMENT)
    }
  })

  it('lets both apps sign the read-state kind', () => {
    // Read state is a property of the person, not the app (CRO-2, ADR 0001
    // layer 2), so both write it and neither owns it. Granting one would make
    // "read it in Ship, it is read in Peek" true in one direction only.
    for (const client of ['estiva-ship', 'estiva-peek']) {
      expect(app(client).allowedKinds).toContain(30078)
    }
  })

  it('lets Peek sign the DM commands, and not the relay-signed snapshot', () => {
    const allowed = app('estiva-peek').allowedKinds
    for (const kind of [41010, 41011, 41012]) expect(allowed).toContain(kind)
    // 30622 is relay-signed and result-gated: the relay republishes it and a
    // reader must equal its `#p`. Granting it would let Peek forge a
    // visibility snapshot, and ingest would refuse it anyway. The absence is
    // the decision, so it is asserted rather than left to be re-added by
    // somebody completing the set.
    expect(allowed).not.toContain(30622)
  })

  it('lets Peek sign relay auth, and never without a relay to sign it for', () => {
    // PEE-4, and the assertion this replaces was the previous half of it: while
    // `policy.ts` had no `relay`-tag branch, the grant alone was a widening, so
    // 22242 was pinned *absent* to force the pairing. The pairing exists now, so
    // what is worth asserting is the pairing itself rather than either number.
    //
    // Stated in both directions on purpose. The kind without a relay list is an
    // app that authenticates nowhere — a `/sign` that passes the kind check and
    // is then refused for every relay there is, which is PEEK-133's shape. A
    // relay list without the kind is inert, and would sit there looking like a
    // grant until somebody added 22242 and got no scope with it.
    for (const seeded of SEED_APPS) {
      expect(
        seeded.allowedKinds.includes(22242),
        `${seeded.clientId}: 22242 and relayAuthUrls must agree`,
      ).toBe(seeded.relayAuthUrls().length > 0)
    }
    expect(app('estiva-peek').allowedKinds).toContain(22242)
  })

  it('does not let Ship sign relay auth', () => {
    // Ship reads the relay over the HTTP bridge and opens no socket, so it has
    // no challenge to answer. Asserted rather than left absent because the
    // natural instinct on the next socket ticket is to grant both apps at once.
    expect(app('estiva-ship').allowedKinds).not.toContain(22242)
    expect(app('estiva-ship').relayAuthUrls()).toEqual([])
  })

  it('scopes Peek to the deployment’s relays and nothing wider', () => {
    // The app column can only narrow — `policy.ts` ANDs it with the deployment
    // bound — but seeding it from anywhere other than that bound would make the
    // row look like an independent grant.
    expect(app('estiva-peek').relayAuthUrls()).toEqual([...config().SIGN_RELAY_AUTH_ALLOWED_URLS])
    expect(app('estiva-peek').relayAuthUrls().length).toBeGreaterThan(0)
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

  it('lets Peek sign the assertion kind it publishes for itself', () => {
    // PEEK-128: kind:9101 says "this thread is resolved" on the wire, so any
    // app in the suite can read it. Unlike the Change kind above, Peek is not
    // borrowing another app's kind here — it writes this one for itself.
    //
    // Its absence cost a round of live debugging: resolving in Peek published
    // nothing while every signal inside Peek said it had worked. The Convex row
    // resolved, the card rendered resolved, and `/sign` refused with
    // `kind_not_allowed` in a console line nobody was watching.
    expect(app('estiva-peek').allowedKinds).toContain(PEEK.ASSERTION)
  })

  it('lets Peek sign the metadata edit a topic rename is', () => {
    // Renaming needed no Buzz change — the relay already applies a `name` tag
    // in `handle_edit_metadata` — so the whole feature shipped and then failed
    // only here, with `policy_violation / kind_not_allowed` from `/sign`.
    //
    // The failure is quieter than the two above: the topic *is* renamed in
    // Peek, so every screen is correct and only the relay is unaware, leaving
    // other apps on the old name.
    expect(app('estiva-peek').allowedKinds).toContain(PEEK.EDIT_CHANNEL_METADATA)
  })

  it('lets Peek sign the delete that makes a deleted topic actually gone', () => {
    // PEEK-170. Deleting a topic in Peek removes it, its messages, replies,
    // reactions and huddles from Convex and publishes nothing, so a conversation
    // somebody deleted believing it gone stays readable to every admitted member
    // — 145 messages across 37 channels on prod with zero deletion requests
    // against any of them.
    //
    // 9008 rather than a kind:5 per message, and not for efficiency: Buzz
    // rejects a multi-target kind:5, and NIP-09 is honoured only for the key
    // that signed the original, so per-message deletion can never reach anybody
    // else's messages. Delete-group soft-deletes the channel and Buzz's read
    // guards then hide the whole container regardless of who wrote what.
    //
    // First entry in this list added *before* the code that needs it. The three
    // above were each found by shipping a feature that worked everywhere except
    // `/sign`.
    expect(app('estiva-peek').allowedKinds).toContain(PEEK.DELETE_GROUP)
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
