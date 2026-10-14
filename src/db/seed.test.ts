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

/** Buzz's own kinds, named here because neither app owns them. */
const BUZZ = {
  /** `KIND_STREAM_MESSAGE_EDIT` — an edit is a new event, never a rewrite. */
  MESSAGE_EDIT: 40003,
  /** `KIND_FOLDER_COMMAND` — a client asks; the relay signs the state. */
  FOLDER_COMMAND: 1852,
  /** `KIND_FOLDER_STATE` — relay-signed, and refused from every client. */
  FOLDER_STATE: 30890,
  /** Blossom authorization — a header credential, never stored. */
  BLOSSOM_AUTH: 24242,
  /**
   * `KIND_FILE` — the bare file. Owned by no app (RFC 0.5 §10.7): the generic
   * apps render its aspects, and typed kinds add properties on top of it.
   */
  BARE_FILE: 30840,
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

  it('lets Peek sign the object kinds the apps it acts on declare creatable', () => {
    /*
      PRO-4 made object-creating actions renderable, so Peek draws Ship's
      `add-issue` as a form and publishes the issue itself. It does not choose
      the kind — `buildActionEvent` takes it from `emits.kind` in Ship's own
      manifest — exactly as it does not choose 1851 for a status change.

      This is the fourth ceiling raised after the fact rather than before it
      (1851, 9101, 9002, now 30851), and each time the app was correct, the
      relay was willing, and `/sign` refused at the last step with everything
      else already agreed. Asserted here so the next borrowed kind is a failing
      test rather than a screenshot.

      30850 since MAN-8. This used to assert Peek could *not* sign a project,
      because Ship declared no action creating one. MAN-4 declared
      `add-project` on a Folder, and Peek now offers it there — so the old
      assertion was a /sign refusal waiting for the first person to click.
    */
    expect(app('estiva-peek').allowedKinds).toContain(SHIP.ISSUE)
    expect(app('estiva-peek').allowedKinds).toContain(SHIP.PROJECT)
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

  it('lets Ship sign relay auth, scoped the same way Peek is', () => {
    // This assertion used to be its inverse, named "does not let Ship sign
    // relay auth", because Ship opened no socket and so had no challenge to
    // answer. LIV-1 measured the socket it is about to open and PER-3 adopts
    // it, so the premise is gone; the pairing above is what keeps the reversal
    // from being an unscoped grant.
    //
    // Scoped from the deployment bound and nowhere else, for the reason the
    // Peek case below gives: a list from any other source would read as an
    // independent grant rather than as a narrowing of one.
    expect(app('estiva-ship').allowedKinds).toContain(22242)
    expect(app('estiva-ship').relayAuthUrls()).toEqual([...config().SIGN_RELAY_AUTH_ALLOWED_URLS])
    //
    // Deliberately no `toBeGreaterThan(0)` here. Under vitest that length is
    // the fixture in `src/test/setup.ts`, so asserting it would test the
    // fixture and read as though it had settled the deployment — which is the
    // one thing this file cannot do. The box is where that is checked.
  })

  it("lets Leaf sign in and write Leaf 1's pages, changes and comments, sent back only to its own addresses", () => {
    // A kind here Leaf does not use is a grant nobody asked for, so the list is
    // exact rather than `toContain`: adding a kind for Leaf should have to
    // change this line. Never 30890, which the relay signs.
    expect([...app('estiva-leaf').allowedKinds].sort((a, b) => a - b)).toEqual([
      5, 1111, 1851, 1852, 22242, 24242, 27235, 30840, 40003,
    ])
    expect(app('estiva-leaf').relayAuthUrls()).toEqual([...config().SIGN_RELAY_AUTH_ALLOWED_URLS])
    expect(app('estiva-leaf').redirectUris()).toEqual([...config().LEAF_REDIRECT_URIS])
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

  it('lets Peek sign a bare file, because a topic is one', () => {
    // RFC 0.5 §10.7, decided 2026-09-11. A new topic is a `kind:30840` inside
    // a team's channel, and its messages are `kind:1111` comments on it —
    // which Peek could already sign. The relay has carried `KIND_FILE` as a
    // member write since NIP-FC; this ceiling was the only gate left, and it
    // refuses as `422 kind_not_allowed` after the app has reported success.
    //
    // Peek only. Ship creates no bare files this week, and the checklist's
    // lesson is that a grant nobody exercises is a grant nobody notices is
    // wrong — the assertion is pinned in both directions so widening it is a
    // decision rather than a drift.
    expect(app('estiva-peek').allowedKinds).toContain(BUZZ.BARE_FILE)
    expect(app('estiva-ship').allowedKinds).not.toContain(BUZZ.BARE_FILE)
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

  it('lets both apps sign the message edit, because an edit is a new event', () => {
    // CON-4 and CON-8. A kind:9 and a kind:1111 are both non-replaceable, so an
    // edit cannot overwrite what it edits — it is a separate kind:40003 naming
    // its target, and an app without the grant can only patch its own database.
    // Peek does exactly that today: `editBody` publishes nothing, so a human
    // edit never leaves the app and every other reader keeps the old text.
    //
    // Both apps or neither. One app able to publish an edit the other cannot is
    // the asymmetry CON-4 exists to prevent, and it would be invisible until
    // somebody edited a comment and watched it not travel.
    for (const client of ['estiva-peek', 'estiva-ship']) {
      expect(app(client).allowedKinds).toContain(BUZZ.MESSAGE_EDIT)
    }
  })

  it('grants the edit to the agent too, which now has comments to edit', () => {
    /*
      This asserted the opposite until AGE-3, on the ground that `claude-agent`
      "files and comments through Ship's own kinds; nothing in it edits a
      published message". The second half stopped being true: estiva-agent#39
      adds `ship edit-comment` and `peek edit`, and both publish a 40003.

      The ceiling is a union of what an identity writes, and the agent writes
      the comments it would be editing — the same argument that put 9 and 1111
      on the row, not a widening for its own sake. Nothing about *who* may edit
      changes: `validate_edit_ownership` still accepts only the target's
      effective author or the NIP-OA owner of an authoring agent, so this grant
      lets the agent edit what it wrote and nothing else.

      Blossom below stays refused, and is the negative control that keeps this
      file from reading as "the agent gets whatever it asks for".
    */
    const agent = SEED_APPS.find((seeded) => seeded.clientId === 'claude-agent')
    if (agent) expect(agent.allowedKinds).toContain(BUZZ.MESSAGE_EDIT)
  })

  it('says out loud that the agent is not seeded here, so this file cannot enforce it', () => {
    /*
      **`claude-agent` is not in `SEED_APPS`.** Its row on production was made
      by hand, so both assertions above are `if (agent)` — no-ops — and the
      grant AGE-3 needs is a `psql` update on the box rather than a re-seed.

      Worth an assertion rather than a comment, because the guard is invisible
      at a glance: somebody reading a green suite would reasonably conclude the
      ceiling above is the one production holds, and it is not. If the agent is
      ever added to `SEED_APPS`, this fails and the two tests above start
      meaning something — which is the moment to check the hand-made row's
      other columns before a seed overwrites them.
    */
    expect(SEED_APPS.find((seeded) => seeded.clientId === 'claude-agent')).toBeUndefined()
  })
})

describe('the Folder command', () => {
  it('is signable by both apps, because both navigate by Folder', () => {
    // Not a cross-app grant like Peek's 30851: 1852 is a kind neither app owns
    // and both write, the way 9007 already is.
    for (const client of ['estiva-peek', 'estiva-ship'] as const) {
      expect(app(client).allowedKinds).toContain(BUZZ.FOLDER_COMMAND)
    }
  })

  it('lets both apps rename a Folder, and only Peek delete one (FOL-8)', () => {
    // A rename is `9002` on the channel, then `1852` on the state; without the
    // first, Ship could create a Folder and never rename it — measured on
    // production, 2026-09-29. Deleting stays out of Ship by decision.
    for (const client of ['estiva-peek', 'estiva-ship'] as const) {
      expect(app(client).allowedKinds).toContain(PEEK.EDIT_CHANNEL_METADATA)
    }
    expect(app('estiva-ship').allowedKinds).not.toContain(PEEK.DELETE_GROUP)
  })

  it('does not grant the state kind to anybody', () => {
    // `is_relay_only_kind` refuses a 30890 from any client, so a ceiling that
    // allowed it would be wider than the wire — and a refusal whose reason is
    // in a different service is the hardest kind to read.
    for (const client of ['estiva-peek', 'estiva-ship'] as const) {
      expect(app(client).allowedKinds).not.toContain(BUZZ.FOLDER_STATE)
    }
  })

  it('lets both apps sign a Blossom authorization, for reading as well as writing', () => {
    // CON-12. Not only about uploading: media GET is unconditionally
    // authenticated on the deployed relay, so without this an app cannot
    // *display* an attachment another app posted. Ship's need is that read
    // half — SHI-1's screenshots — which is why it is not Peek-only.
    for (const client of ['estiva-peek', 'estiva-ship'] as const) {
      expect(app(client).allowedKinds).toContain(BUZZ.BLOSSOM_AUTH)
    }
  })

  it('does not grant Blossom to the agent, which has no blobs', () => {
    // The ceiling is a union of what an identity actually writes. The agent
    // files and comments; it uploads nothing and renders nothing.
    const agent = SEED_APPS.find((seeded) => seeded.clientId === 'claude-agent')
    if (agent) expect(agent.allowedKinds).not.toContain(BUZZ.BLOSSOM_AUTH)
  })
})
