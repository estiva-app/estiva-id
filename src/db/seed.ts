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
    // Deliberately NOT 22242 either, and that one is not an omission — see the
    // PR. NIP-42 relay auth needs a scoping control in `policy.ts` alongside
    // the grant (PEE-4), because unqualified it lets Peek mint relay-auth
    // credentials for any relay at all. The grant without the control is a
    // widening, so the two land together or not at all.
    allowedKinds: [9, 7, 5, 9007, 27235, 1851, 9101, 9002, 9008, 1111, 30078, 41010, 41011, 41012],
    nip98UrlPrefixes: [],
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
    allowedKinds: [30850, 30851, 1851, 9, 5, 9007, 31989, 27235, 1111, 30078],
    nip98UrlPrefixes: [],
    redirectUris: () => [...config().SHIP_REDIRECT_URIS],
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
         (client_id, name, allowed_kinds, nip98_url_prefixes, redirect_uris)
       values ($1, $2, $3, $4, $5)
       on conflict (client_id) do update
         set name = excluded.name,
             allowed_kinds = excluded.allowed_kinds,
             nip98_url_prefixes = excluded.nip98_url_prefixes,
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
