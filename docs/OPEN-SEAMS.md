# Seams — what is decided, and what is still open

Two questions were deliberately left open while the service was built. **Both
are now decided** (2026-08-04). This page records the decisions, why they were
made, and what remains to implement — followed by the smaller things still open.

---

## DECIDED · Domain layout and `nip05` (PEEK-33)

**Decision: the relay serves `/.well-known/nostr.json`. Estiva ID stays
authoritative by being the sole publisher of `kind:0` — the handle rides in the
profile event.**

> **This reverses an earlier decision, deliberately.** The first answer was that
> Estiva ID would serve `nostr.json` itself, exposed at the community domain by
> routing that one path to it. That reasoning was sound for a **single**
> workspace and wrong for many. The reversal is recorded rather than quietly
> applied, because the original argument still holds in the case it was made for.

### The constraint

A `nip05` handle maps a name to a pubkey — `jan@abc.estiva.app` rather than
`714902a6…` — resolved by fetching
`https://<domain>/.well-known/nostr.json?name=jan`. There is no registry:
**whoever controls the domain controls what the handle means.** That is why the
handle is the org's *attestation*, and why revoking it is deleting a line from a
file.

Three facts from the relay source pin this down harder than the issue suggests:

1. **`communities.host` is one hostname per community**, resolved per request
   from the `Host` header (`crates/buzz-relay/src/tenant.rs`). The same binding
   governs WebSocket connections, the bridge API *and* `nostr.json`.
2. **`extract_domain()` does not strip subdomains** — it removes only scheme,
   port and path, so `abc.estiva.app` stays `abc.estiva.app`
   (`crates/buzz-relay/src/api/nip05.rs`).
3. **`canonicalize_nip05()` requires the handle's domain to equal the tenant host
   exactly**, and runs during profile sync (`handlers/side_effects.rs`).

Together: **the domain inside a handle is welded to the hostname the relay
answers on.** Serving `nostr.json` elsewhere does not change what the handle
must say.

### Why the relay, and not this service

Because workspaces are per-customer. Each company gets its own community host —
`abc.estiva.app` now, `chat.acme.com` when custom domains arrive — and handles
follow it. That means `nostr.json` has to answer at **every customer's domain**.

For Estiva ID to serve it, this service would have to be reachable on all of
those hostnames and implement its own `Host` → workspace binding: the
fail-closed lookup, the "never reveal which communities exist on this
deployment" behaviour, all of it. Buzz already has that, with a formal isolation
spec behind it (`docs/multi-tenant-relay.md`), and its `nostr.json` endpoint
already sets `Access-Control-Allow-Origin: *`.

Reimplementing a verified tenant seam to own a file is the wrong trade. Estiva
ID keeps authority where it belongs — as the only publisher of `kind:0`.

### The revocation question this reopens — measured, not inferred

Serving from the relay means revoking a handle is a *publish*, not a local
delete: Estiva ID republishes the person's `kind:0`, the relay syncs it.

**Omitting the field revokes the handle, and so does an empty string.** Both
spellings work.

This reverses what was written here first. Reading `buzz-db/src/user.rs`
suggested the update only touches `nip05_handle` when a value is present — so a
`kind:0` with no `nip05` would leave the previous handle standing, and a leaver
would keep their badge. That inference was wrong, and it was load-bearing enough
that it should never have been left as an inference: measuring it against the
live relay took four minutes. The probe is kept at
`estiva-ship/scripts/probe-nip05.ts` because it is cheap to re-run and Buzz's
sync behaviour here is undocumented — if it ever changes, that is what notices.

Estiva ID emits the *absent* spelling: `buildProfile` drops empty values, so a
cleared handle produces a `kind:0` with no `nip05` at all
(`src/nostr/event.ts`, pinned by a test).

One caveat from the same reading still stands and is **not** disproven: a handle
that fails canonicalisation is *not applied* rather than clearing what is there.
A `kind:0` whose handle domain does not equal `communities.host` is discarded
silently, which is why the host is assembled at publish time rather than stored
joined (PEEK-59).

### Still to implement

* ~~Publishing `kind:0` with the handle (PEEK-31)~~ — done: `src/domain/profile.ts`
  signs and publishes through the relay's `POST /events` bridge, using
  `withUserSecretKey` rather than `/sign`, whose `kind:0` refusal stays absolute.
* ~~A handles table keyed by **`(person, workspace)`**, not by person~~ — done:
  `user_handles(user_id, community_host, handle)`, keyed by host so no
  `workspaces` table is needed before PEEK-83 wants one.
* ~~Confirm the revocation semantics above, with a test against a real relay.~~ — done, above.
* `communities.host` seeded per workspace (PEEK-59) — seeded for
  `estiva.estiva.app`; the relay answers NIP-11 there, so the tenant resolves.
* ~~Remove Peek's publisher (`peek-app/convex/nostr/publish.ts`)~~ — done.
* Remove Ship's publisher (`estiva-ship/src/store.ts`) — **blocked, and not on
  effort.** Ship mints its key per-browser in localStorage
  (`localIdentity('ship.secretkey')`, `apps/ship/app.ts`) and has no Estiva ID
  integration at all. Estiva ID does not custody that key, so removing Ship's
  publisher would delete the only writer rather than move it, and every Ship
  author would render as 64 hex characters. Ship needs its equivalent of Peek's
  *Accept Estiva ID tokens alongside Convex Auth* first.

  Until then "published once" holds for Peek and is still a policy for Ship.

### Consequence to act on now

Authentication is **centralised**, and does not follow the workspace domain.
Everyone signs in at one origin regardless of which workspaces they belong to,
which is what keeps "one human, one pubkey" true for a contractor working with
two client companies.

Planned hostnames:

| Hostname | What |
| --- | --- |
| `estiva.app` | Marketing only. No app traffic, no relay traffic. |
| `id.estiva.app` | Estiva ID. `ISSUER_URL=https://id.estiva.app` |
| `abc.estiva.app` | A customer workspace: their relay, their community host, their handles (`jan@abc.estiva.app`) |
| `chat.acme.com` | The same, once customers can bring their own domain |

**Set `RP_ID=estiva.app`, not `id.estiva.app`.** WebAuthn permits the RP ID to be
a registrable-domain suffix of the origin, so a service at `id.estiva.app` may
claim `estiva.app`. That way passkeys survive the service ever moving to another
subdomain; pinning the narrower value means every credential dies on such a move,
with no migration path.

This does not loosen anything, because the two settings do different jobs:
`RP_ID` decides which credentials an authenticator will *offer*, while
`RP_ORIGINS` decides which origins this service will *accept an assertion from*.
Keep `RP_ORIGINS` to exactly `https://id.estiva.app` and a compromised sibling
subdomain cannot use those passkeys — the origin inside `clientDataJSON` will not
match. **The residual cost is that this holds only while that allowlist stays
tight.** Do not widen it casually.

---

## Multi-workspace: shared now, dedicated deployments later

Recorded here because it constrains work that has not started, and because the
Stage 1 plan originally assumed a single workspace throughout.

**The goal:** one shared deployment now, so small companies can be onboarded
quickly to try Estiva; **dedicated per-workspace deployments** as the long-term
enterprise story.

### The invariant that keeps "dedicated later" cheap

**A person's pubkey must not change when their workspace is split out.** If it
does, every message and issue they ever wrote stays on the relay signed by a key
that is no longer theirs, and their history detaches from them — the same class
of unrecoverable failure the Stage 2 key migration guards against.

The custody format already supports this, without change. Because each secret is
encrypted under its own random DEK and only the DEK is wrapped per deployment,
extracting a customer is: add a wrap under the new deployment's KEK, ship the
envelope rows, drop the old wrap. **No user secret is re-encrypted and no pubkey
changes.** The mechanism built for escrow turns out to serve tenant extraction
too — see [KEY-CUSTODY.md](KEY-CUSTODY.md).

### What a split does change, unavoidably

The **issuer URL**. Tokens name their issuer and apps trust an issuer, so a
customer moving to their own deployment means repointing their apps at a new
issuer and JWKS, ending every live session at that moment. Planned maintenance,
not a background migration. Fine — as long as nobody promises otherwise.

### What the schema already gets right

Under "one human, one pubkey", a contractor at two client companies is **one row
here**, not two:

* `users.email` globally unique — correct.
* One active key per user — correct, same reason.
* `workspaces` and `workspace_members` are an ordinary later migration.

### The one thing that would be wrong if built carelessly

**A handle belongs to a `(person, workspace)` pair, not to a person.** Jan may be
`jan@abc.estiva.app` in one workspace and `jan@chat.acme.com` in another, with
the same pubkey. A single `nip05_handle` column on `users` is the shape that has
to be undone later.

This matches Buzz's own rule that profiles do not inherit across community
domains — a pubkey in two communities reposts its profile in each.

---

## DECIDED · Who drives community admission (PEEK-36)

**Decision: Estiva ID observes admission state and displays it. It does not
drive it — yet.**

### The constraint

Onboarding is two operations against two systems: create an identity here, and
admit the pubkey to the Buzz community. Buzz owns the second and should keep it
— the relay checks membership at authentication time against a
`pubkey_allowlist`, **fail-closed** on database error, with ban/timeout state
checked before the allowlist even runs. It is formally verified
(`Inv_AdmissionFence`) and it is the right place for the gate.

The open question was only who presses the button.

### Why this option

The two failure modes of a manual two-step are not equally bad:

* **Half-onboarded** — identity exists, never admitted. Annoying. Someone
  complains on day one and it is fixed in a minute.
* **Half-offboarded** — removed here, still admitted at the relay. A security
  problem, and a *silent* one: nothing in either system surfaces the mismatch.

Observing closes the dangerous half without taking on a write dependency on
Buzz's control plane. If that API changes, the people list shows "unknown"
rather than corrupting state. And it puts the interface in place, so moving to
Estiva ID *driving* admission later is filling in a method rather than
redesigning a surface.

**The intended end state is still one-action onboarding and offboarding.** This
is a staged route to it, not a rejection of it.

### Implemented on 2026-08-10, with the people list (PEEK-64)

* ~~A read-only admission port: `getAdmissionStatus(pubkey) → admitted | not-admitted | unknown`~~
  — `src/domain/admission.ts`, plus a batch form so a real implementation is not
  N+1 across a page of people.
* ~~`unknown` as an honest state, shown as such~~ — rendered "Relay: Not known"
  in a muted chip, with the detail view naming `buzz-admin list-members` as
  where the real answer lives.
* ~~Per-person display of identity **and** admission~~ — one row carries account
  status, enrolment and admission, and an ordinary `active` draws no chip at all,
  so the one amber chip on the row that matters is not lost in a wall of green.

**And a finding that hardens this decision rather than softening it: `unknown`
is not a default, it is the only reachable answer.** The relay's HTTP surface has
no membership read endpoint — `crates/buzz-relay/src/router.rs` exposes the
bridge, media, NIP-05 and a moderation API covering reports and feedback, and
nothing else. `buzz-admin list-members` is a CLI that opens Buzz's Postgres
directly (`connect_db()` in `crates/buzz-admin/src/main.rs`).

So Estiva ID could only answer this by connecting to another service's database,
which is exactly the coupling §3 of [ARCHITECTURE.md](ARCHITECTURE.md) exists to
refuse — and it would be the first thing to unpick when workspaces get dedicated
deployments. Observing admission properly therefore needs *Buzz* to grow a read
endpoint. Until it does, the honest display is the whole of the mitigation.

A third enrolment dimension came out of building this and is worth recording,
because it is a state neither system named before: **`enrolling`** — the invite
was opened, a user row and a custodied key exist, and the passkey prompt was
dismissed. That person owns a pubkey and cannot sign in. It is the commonest way
enrolment fails, it is invisible from every other angle, and it is now on the
list as "Never signed in".

`users.status` (`active` / `suspended` / `offboarded`) describes only *this
service's* view and deliberately does not claim to represent relay admission.

### Known and accepted: offboarding is not instant everywhere

The relay side is immediate — pull admission and they are locked out. But Peek
validates tokens **statelessly** against JWKS; it does not check whether someone
is still employed, only that the signature and expiry hold. A leaver with a live
token keeps their Peek session until it expires.

That window is `JWT_TTL_SECONDS`, currently **600 seconds**. It is a config
value, not a rewrite. Recorded so it is a decision rather than a surprise.

---

## Still open

* **Recovery.** No account-recovery path. Enrolling a second passkey requires an
  existing session, which you cannot get on a new device if you lost the only
  one. Cross-device enrolment normally happens client-side via WebAuthn hybrid
  transport (the QR flow), so the server seam is right — but "I lost my laptop"
  has no server-side answer in Stage 1. Revoking your last passkey is refused
  for this reason.
* **Registration is open.** Anyone who can reach the origin can create an
  account. Invite-gated enrolment is PEEK-65.
* **KEK rotation** is expressible in the envelope format but has no procedure —
  see [KEY-CUSTODY.md](KEY-CUSTODY.md).
* **Audit retention.** The log is read now — `GET /admin/audit` and the History
  screens (PEEK-69) — but nothing prunes or archives it. It grows forever, and a
  restore brings all of it back. Fine at Stage 1 volumes; it needs a policy
  before it is not, and that policy is a *decision* (how long must an
  offboarding stay visible?) rather than a cron job.

  Building the reader also turned up the gap that mattered more than the
  reader: **`setUserStatus` wrote no record at all.** Offboarding — the one
  action the custody argument most depends on being visible — was the one
  action that left no trace. It records now, naming the actor, the subject, and
  what the status changed *from*, which is what separates an admin restoring
  access from an admin seizing an account.
* **Multi-community.** One workspace is assumed throughout; see
  [ARCHITECTURE.md](ARCHITECTURE.md) §8.
