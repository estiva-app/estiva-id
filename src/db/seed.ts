/**
 * Development seed: the two app credentials the suite already needs.
 *
 * The kind lists come from PEEK-71 and are knowable from what each app
 * publishes today. They live in the database rather than in code because the
 * set changes when an app gains a feature, and that should not be a deploy of
 * the identity service.
 *
 * NIP-98 prefixes are left empty on purpose: the relay bridge host follows from
 * the undecided domain layout (PEEK-33), and an empty list refuses all 27235.
 */
import { config } from '../config.js'
import { closePool, query } from './pool.js'

interface SeedApp {
  clientId: string
  name: string
  allowedKinds: number[]
  nip98UrlPrefixes: string[]
  /**
   * Relays this app may answer a NIP-42 challenge from (PEE-4).
   *
   * A thunk, and stated per app rather than defaulted from the deployment the
   * way `nip98UrlPrefixes` is below. The two lists differ in who needs them:
   * every app needs the bridge, so defaulting there prevents a credential that
   * holds 27235 and can reach nothing. Only Peek answers relay challenges, so
   * defaulting here would hand a relay to apps that have no business
   * authenticating to one — and would make a later `22242` on some other app's
   * row an unscoped grant, silently, because its relay list was already full.
   *
   * The invariant to keep: an app has a non-empty list here **iff** it has
   * 22242 above. `seed.test.ts` asserts both directions.
   */
  relayAuthUrls: () => string[]
  /** Where `/authorize` may send this app back to. Exact match — see config. */
  redirectUris: () => string[]
}

/**
 * Apps default to whatever this deployment allows, rather than a hardcoded
 * hostname — the relay's address differs per workspace and per environment, and
 * `SIGN_NIP98_ALLOWED_URL_PREFIXES` is already the single place that says it.
 *
 * Seeding both apps identically does not make the per-app column pointless: it
 * is the ceiling that can be lowered later, e.g. to bar an app from
 * `/media/upload` while still letting it publish. Widening is impossible — the
 * deployment bound always applies as well.
 */
const relayPrefixes = (): string[] => [...config().SIGN_NIP98_ALLOWED_URL_PREFIXES]

export const SEED_APPS: readonly SeedApp[] = [
  {
    clientId: 'estiva-peek',
    name: 'Estiva Peek',
    // PEEK-71: 9 (chat message), 7 (reaction), 5 (deletion), 9007 (huddle).
    // 27235 is NIP-98 HTTP auth — without it the app cannot authenticate to the
    // relay's bridge at all, so it can hold a signed event and still not publish.
    //
    // 1851 is Ship's Change kind, and it is here because **acting on another
    // app's object means writing that app's kind**. Peek does not choose it:
    // `buildActionEvent` takes the kind from the target app's own manifest
    // (`manifest.records`), so a status change on a Ship project is necessarily
    // a kind:1851. Without it `/sign` refuses with `kind_not_allowed` and the
    // action fails at the last step, after the manifest has already agreed.
    //
    // This is a ceiling, not a grant of meaning: it says Peek may sign a 1851,
    // not that Peek decides what one means. The relay still applies its own
    // membership and authorization checks. Any further cross-app action Peek
    // offers will need the same treatment — the kind list has to be the union
    // of what Peek writes for itself and what the apps it acts on declare.
    // 9101 is the Estiva assertion (PEEK-128) — "this thread is resolved",
    // said on the wire so any app in the suite can read it. Peek writes it for
    // itself, so unlike 1851 above this is not borrowed from another app's
    // manifest.
    //
    // Its absence is the failure this comment block already warns about, two
    // paragraphs up, and it still cost a round of live debugging: resolving
    // published nothing, and every signal inside Peek said it had worked. The
    // Convex row resolved, the card rendered resolved, and `/sign` refused with
    // `kind_not_allowed` in a console line nobody was watching. A ceiling that
    // is too low fails at the last step, after everything else has agreed.
    //
    // 9002 is NIP-29 edit-channel-metadata — renaming a topic. Peek writes it
    // for itself, like 9101 above. Buzz needed no change for renames because it
    // already applies a `name` tag in `handle_edit_metadata`, and it grants that
    // to a channel's owner or admin only — so this ceiling says Peek may sign
    // the kind, not that any given rename is permitted.
    //
    // Third time now: 1851, then 9101, now this. Each one shipped, worked
    // everywhere it was checked, and failed at `/sign`. Renaming was the
    // clearest yet — the topic really is renamed locally, so the app is correct
    // and the relay simply never hears, and only a warning under the dialog
    // distinguishes that from success.
    //
    // 9008 is NIP-29 delete-group, and it is the first entry here added *before*
    // the code that needs it rather than after that code failed in production.
    //
    // Deleting a topic in Peek deletes it, its messages, replies, reactions and
    // huddles from Convex and publishes nothing at all. Create propagates as a
    // 9007; delete propagates nowhere. So a conversation somebody deleted
    // believing it gone stays readable to every admitted member indefinitely —
    // measured on prod at 145 messages across 37 stream channels with **zero**
    // deletion requests against any of them (PEEK-170).
    //
    // 9008 rather than a kind:5 per message, and the difference is not
    // efficiency. Buzz rejects a multi-target kind:5 outright ("deletion events
    // must reference exactly one target"), and NIP-09 is honoured only for the
    // key that signed the original — so per-message deletion can never reach
    // anybody else's messages in the topic. Delete-group soft-deletes the
    // channel, and Buzz's read guards (`c.deleted_at IS NULL` in both
    // `get_accessible_channels` and `is_member`) then make the whole container
    // unreadable, whoever wrote what is in it.
    //
    // A ceiling, not a grant: Buzz enforces "only owner can delete group" in
    // `validate_admin_event`, so this says Peek may sign the kind, not that any
    // given delete is permitted.
    // 1111 is NIP-22, and Peek needs it for the same reason Ship does — but a
    // step removed, which is why it is easy to miss. Peek does not decide to
    // publish a comment kind; `buildActionEvent` stamps whatever the *owning
    // app's* NIP-89 manifest declares. So the moment Ship's manifest says
    // `1111` (REW-10), Peek's comment action starts signing `1111` without
    // anyone changing a line of Peek. Without this it fails at `/sign` — after
    // the manifest has already offered the action, which is exactly how the
    // kind:1851 case failed in the demo.
    // 30078 is NIP-78 app-specific data, and it is where read state lives
    // (CRO-2, and ADR 0001's layer 2). Already in Buzz's ALL_KINDS, so the
    // relay takes it today and this ceiling is the only gate. No `t`-tag or
    // URL-prefix constraint applies — `nip98_url_prefixes` is specific to
    // kind:27235, so there is nothing else to configure.
    //
    // 41010/41011/41012 are the DM commands (DMS-1): open a DM, add a member
    // — which creates a *new* DM with the expanded set — and hide one. kind:9
    // is already here and is what DM messages themselves are.
    //
    // Deliberately NOT 30622. `KIND_DM_VISIBILITY` is relay-signed: the relay
    // republishes it on every hide, `buzz-core` lists it in
    // RESULT_GATED_KINDS, and a reader must equal the event's `#p`. Peek only
    // ever reads its own. Granting it would let Peek forge a visibility
    // snapshot, and ingest would refuse it anyway as relay-signed-only.
    //
    // 22242 is NIP-42 relay auth (PEE-4), and it is the one entry in this list
    // that is **not** safe on its own. Every other kind here is a thing Peek
    // publishes; a 22242 is a challenge response, so signing one proves to a
    // relay that this user is present at it. Unqualified, that is "Peek may be
    // this person at any relay on the internet".
    //
    // So it lands paired with `relayAuthUrls` below and with the `relay`-tag
    // branch in `domain/policy.ts`, which ANDs that column against
    // SIGN_RELAY_AUTH_ALLOWED_URLS. Neither half is useful alone and neither is
    // safe alone: the kind without the scope is a widening, and the scope
    // without the kind is inert.
    //
    // The relay requires NIP-42 before it accepts a subscription
    // (`auth_required: true`), so without this every REQ on an otherwise
    // healthy socket returns `auth-required: authenticate before subscribing`.
    // Same shape as the three /sign refusals above — everything looks connected
    // and nothing arrives — reached down a different path, because here it is
    // the relay refusing rather than `/sign`. Like 9008, it is added before the
    // code that needs it: M3's socket work cannot be tested until it is live.
    // 30851 is Ship's Issue, and it is the second entry here borrowed from
    // another app's manifest rather than written by Peek for itself — 1851
    // above was the first, and this is the same rule one step further.
    //
    // PRO-4 made object-creating actions renderable, so Peek now draws Ship's
    // `add-issue` as a form and publishes the issue itself. Peek does not
    // choose the kind any more than it chose 1851: `buildActionEvent` takes it
    // from `emits.kind` in Ship's own manifest. An action a consumer can render
    // and cannot sign is the worst of both — the form fills in, the parent
    // resolves, and `/sign` refuses at the last step.
    //
    // **Fourth time.** 1851, then 9101, then 9002, now this, and the paragraph
    // three above already said it: "any further cross-app action Peek offers
    // will need the same treatment — the kind list has to be the union of what
    // Peek writes for itself and what the apps it acts on declare." Knowing the
    // rule did not make anyone apply it, because nothing checks. The standing
    // fix is for Peek to read `allowed_kinds` off its own token and decline to
    // offer what it cannot sign, the way `estiva-agent`'s `refuseUnsignable`
    // does; filed rather than done here, because someone is blocked now.
    //
    // 40003 is Buzz's message edit (`KIND_STREAM_MESSAGE_EDIT`), and Peek needs
    // it for CON-8. Peek already *has* an edit control; `editBody` patches the
    // Convex row and publishes nothing, so a human edit never leaves the app
    // and every other reader keeps showing the old text. That is a grant
    // arriving to fix a feature that looks finished rather than to enable a new
    // one.
    //
    // 30850 is Ship's Project, and the reason it was withheld stopped being true.
    // This said "only 30851, not 30850: Ship declares no action that creates a
    // project". Since MAN-4 it does — `add-project`, `appliesTo: "39000"`, a
    // project made in a Folder — and since MAN-8 Peek offers it on a Folder
    // (interop 0.40.0 borrows a creation another app declares on a kind). Peek
    // takes the kind from `emits.kind` in Ship's manifest, as with 30851 above;
    // the Folder command that lists it is 1852, already granted below. **Sixth
    // time** — granted with the change that needs it, not after /sign refuses.
    //
    // **Fifth time**, and the paragraph above predicted it. 1852 is the Folder
    // command: a client asks the relay to change a Folder's contents and the
    // relay emits the state it signs itself (RFC 0.4 §4.1). Both apps navigate
    // by Folder, so both write it — this is not a cross-app grant like 30851,
    // it is a kind neither app owns and both use.
    //
    // Only 1852, not 30890. The state event is relay-signed by construction and
    // `is_relay_only_kind` refuses it from any client, so granting it here
    // would hand an app a kind the relay would reject anyway — a ceiling wider
    // than the wire, which is the shape that makes a refusal hard to read.
    // 24242 is Blossom authorization, and it is **27235 for blobs** rather than
    // a new kind of power. Like NIP-98 it is never stored: it is signed, put in
    // an `Authorization: Nostr <base64url(event)>` header, and read once. The
    // relay's media routes take nothing else — `PUT /upload` for the bytes and
    // `GET /media/{sha256}` for them back, both refused without it.
    //
    // **Reading needs it too, which is the half that surprises.** Media GET is
    // unconditionally authenticated on the deployed relay: the
    // `BUZZ_REQUIRE_MEDIA_GET_AUTH` flag is inert on `nfb-demo-kinds`, and a
    // GET with no header answers 401 rather than 404 (probed 2026-09-08). So an
    // app cannot even *display* an attachment somebody else posted without
    // this, which is why Ship gets it as well as Peek (CON-12).
    //
    // Narrow by construction, and worth stating because "may sign an upload
    // authorization" sounds broad: each event names one verb (`t upload` or
    // `t get`), one blob (`x <sha256>`), and carries an `expiration`. It
    // authorises one action on one already-hashed blob, and the relay checks
    // membership on top of it.
    //
    // **30840 — a topic is a bare file (RFC 0.5 §10.7, decided 2026-09-11).**
    // A new Peek topic is no longer a channel but a file *inside* a team's
    // channel: `kind:30840` carrying `h`, with its conversation as `kind:1111`
    // comments on it — the shape Ship's issues already have, and `1111` is
    // already above. The kind is owned by no app on purpose (the generic apps
    // handle it), so Peek is the first producer rather than the owner. Already
    // registered on the relay (`KIND_FILE`, `MessagesWrite`); this was the only
    // gate left. Not granted to Ship: it creates no bare files yet, and a grant
    // nobody exercises is a grant nobody notices is wrong.
    allowedKinds: [
      9, 7, 5, 9007, 27235, 1851, 9101, 9002, 9008, 1111, 30078, 41010, 41011, 41012, 22242, 30851,
      40003, 1852, 24242, 30840, 30850,
    ],
    nip98UrlPrefixes: [],
    relayAuthUrls: () => [...config().SIGN_RELAY_AUTH_ALLOWED_URLS],
    redirectUris: () => [...config().PEEK_REDIRECT_URIS],
  },
  {
    clientId: 'estiva-ship',
    name: 'Estiva Ship',
    // PEEK-71: 30850, 30851, 1851, 9, 5, 31989 — plus 27235, as above.
    //
    // 9007 is the Folder, and it was missing. Ship's own `kinds.ts` calls it
    // "required on every object below" — it is the container each project,
    // issue, change and message carries in its `h` tag. Without it Ship can add
    // objects to a folder somebody else created and cannot create its first
    // one, because `createProject` publishes the Folder before the Project.
    // Listing the object kinds without their container is not a lower ceiling,
    // it is a broken one.
    //
    // The same number is a huddle for Peek, above. That is fine: this list says
    // what an app may sign, not what a kind means, and the two apps are
    // separately bounded.
    //
    // 1111 is NIP-22, and it is how Ship's comments are moving (REW-10). Today
    // a comment is a kind:9 into the project's Folder carrying an `a` tag; the
    // tag is already standard and the kind is not. `1111` scopes a threaded
    // comment to an *addressable* event, which is what lets two apps comment on
    // the same object without either owning the comment kind — Peek publishes
    // the same shape into the same Folder, and reads the kind off Ship's NIP-89
    // manifest rather than assuming one.
    //
    // Granted before anything writes it, deliberately. Ship's fold already
    // reads `1111` (merged), the relay already accepts it (measured, not
    // inferred from the registry), and this is the last gate that refuses at
    // the final publish rather than at build time. A ceiling that arrives after
    // the code is the reason PEEK-172 exists.
    // 30078 for the same reason as Peek (CRO-2): read state is a property of
    // the person, so both apps write it and neither owns it.
    //
    // 7 is NIP-25, and Ship needs it for CON-2. Peek has had it since it was
    // seeded; Ship has never had it, which is why Ship has no reactions at all
    // rather than broken ones. **Reading them needs no grant** — a `kind:7` is
    // fetched by target and Ship already renders what Peek wrote — so this is
    // only about the half where a person clicks.
    //
    // Narrow by construction, and worth saying because "may sign a reaction"
    // sounds broader than it is: a kind:7 names one target event and carries an
    // emoji, and Buzz derives its channel from that target. It cannot reach a
    // message the signer could not already read, and it changes nothing about
    // the message it points at. Taking one back is a kind:5, which is already
    // here.
    // 40003 is Buzz's message edit (`KIND_STREAM_MESSAGE_EDIT`), for CON-4.
    // Neither app can edit a comment today and both are about to learn how, so
    // the grant lands before the code — the same call as 1111 above, and for
    // the same reason: this is the gate that refuses at the final publish
    // rather than at build time.
    //
    // **This one is genuinely broader than the reaction above, and it is worth
    // not smoothing over.** A kind:7 cannot change what a message says; an edit
    // is exactly that. What bounds it is not the kind but the relay:
    // `validate_edit_ownership` accepts the target's effective author, or the
    // NIP-OA owner of an authoring agent — and for the author path it re-checks
    // channel membership, so somebody removed from a private channel cannot
    // rewrite what they said while they were in it. A kind ceiling cannot
    // express any of that, which is why the ceiling is the wrong place to look
    // for the limit.
    //
    // Channel-scoped: 40003 is in the relay's `requires_h_channel_scope`, so an
    // edit without an `h` is refused with `accepted: false` even though the
    // kind is allowed here and the signature is fine. Two separate gates, and
    // this list is only the first.
    // 1852 is the Folder command, for the reason recorded on Peek's list above.
    // Not 30890: the state is the relay's to sign.
    // 9002 is renaming a Folder (FOL-8, ship#208): NIP-29's edit-metadata on the
    // channel, which Ship publishes before the 1852 that renames the state. Peek
    // has had it for the same act. Refused here on production, 2026-09-29, as
    // "App estiva-ship may not sign kind 9002", after create (9007 + 1852) had
    // worked — so Ship could make a Folder it could not rename. Not 9008:
    // deleting a Folder stays Peek's.
    // 24242 is Blossom authorization — see Peek's entry above for the shape.
    // Ship gets it for the READ half first: media GET is unconditionally
    // authenticated, so without this Ship cannot display an attachment Peek
    // posted, which is SHI-1's screenshot half. Uploading from Ship (SHI-2)
    // uses the same grant.
    //
    // 22242 is NIP-42 relay auth, and it reverses what this entry used to say.
    // See Peek's note above for why it is the one kind in either list that is
    // unsafe unqualified: a challenge response proves to a relay that this
    // person is present at it.
    //
    // **The premise changed, not the risk.** The old comment said Ship "reads
    // the relay over the HTTP bridge and opens no socket, so it has nothing to
    // authenticate", and that was accurate when it was written. LIV-1 then
    // measured the socket Ship is about to open — one connection, one
    // subscription, one filter carrying every Folder's `#h`, delivering 34 of
    // 34 live against production. PER-3 is Ship adopting it, and the relay
    // refuses a REQ before auth outright, so none of it can be proved end to
    // end without this.
    allowedKinds: [
      30850, 30851, 1851, 9, 5, 9007, 9002, 31989, 27235, 1111, 30078, 7, 40003, 1852, 24242, 22242,
    ],
    nip98UrlPrefixes: [],
    // The other half of 22242, and the old comment's own condition: it said the
    // reversal "cannot be a one-line unscoped grant — it has to name a relay
    // too". It does. `seed.test.ts` asserts the pairing in both directions
    // across every seeded app, so the kind cannot land above without this list
    // being non-empty.
    //
    // **That assertion being green proves less than it looks.** It reads
    // `config().SIGN_RELAY_AUTH_ALLOWED_URLS`, and under vitest that is the
    // fixture `ws://relay.test` (`src/test/setup.ts`). A deployment whose own
    // list is empty passes every test in this repo and then refuses this app
    // for every relay there is — `/sign` clears the kind check and the
    // `relay`-tag branch in `domain/policy.ts` ANDs the column down to nothing.
    // That is PEEK-133's shape, and it is why the deployment half is verified
    // on the box against `app_credentials` rather than here.
    relayAuthUrls: () => [...config().SIGN_RELAY_AUTH_ALLOWED_URLS],
    redirectUris: () => [...config().SHIP_REDIRECT_URIS],
  },
  {
    clientId: 'estiva-leaf',
    name: 'Estiva Leaf',
    // A new app (estiva-app/leaf) that saves nothing of its own yet, so the
    // least it can sign in with: 22242 to answer the relay's challenge on its
    // one socket, paired with the deployment's relay list as the other apps'
    // is, and 27235 because every app holds NIP-98 (see the test). Each kind
    // Leaf adds to its `KINDS` has to be added here too, or its first save is
    // refused at /sign after every screen has worked.
    allowedKinds: [27235, 22242],
    nip98UrlPrefixes: [],
    relayAuthUrls: () => [...config().SIGN_RELAY_AUTH_ALLOWED_URLS],
    redirectUris: () => [...config().LEAF_REDIRECT_URIS],
  },
]

/*
  `linear-lite` is gone — phase 3 of PEEK-98, and the last of the rename.

  It was seeded alongside `estiva-ship` so that neither side of the migration
  had to land in a particular minute. Removing it here is only half the job:
  seeding inserts and updates, it never deletes, so the row itself has to be
  dropped by hand on each deployment. Leaving this entry in place would mean the
  next re-seed quietly recreating whatever was deleted.

  Verified idle before removal rather than assumed: the last request under the
  old client id was 2026-08-10T21:20:58Z, well over the four hours a cached
  `bundle.js` can keep an old build alive.
*/

export async function seedApps(): Promise<void> {
  for (const app of SEED_APPS) {
    await query(
      `insert into app_credentials
         (client_id, name, allowed_kinds, nip98_url_prefixes, relay_auth_urls, redirect_uris)
       values ($1, $2, $3, $4, $5, $6)
       on conflict (client_id) do update
         set name = excluded.name,
             allowed_kinds = excluded.allowed_kinds,
             nip98_url_prefixes = excluded.nip98_url_prefixes,
             relay_auth_urls = excluded.relay_auth_urls,
             redirect_uris = excluded.redirect_uris,
             updated_at = now()`,
      [
        app.clientId,
        app.name,
        app.allowedKinds,
        // Empty in the table means "this deployment allows none", so default to
        // the deployment's own list rather than seeding an app that is allowed
        // a kind it can never actually use.
        app.nip98UrlPrefixes.length > 0 ? app.nip98UrlPrefixes : relayPrefixes(),
        app.relayAuthUrls(),
        app.redirectUris(),
      ],
    )
  }
}

if (process.argv[1]?.endsWith('seed.ts') || process.argv[1]?.endsWith('seed.js')) {
  try {
    await seedApps()
    process.stdout.write(`seeded ${SEED_APPS.length} app credential(s)\n`)
  } finally {
    await closePool()
  }
}
