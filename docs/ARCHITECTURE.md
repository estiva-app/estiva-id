# Estiva ID — the design

The identity and user-management app for the Estiva suite. This document is
what you should be able to read instead of re-deriving the design.

Companion documents:

| If you want to… | Read |
| --- | --- |
| Understand the at-rest key format | [KEY-CUSTODY.md](KEY-CUSTODY.md) |
| Know what was decided about domains and admission | [OPEN-SEAMS.md](OPEN-SEAMS.md) |
| Call the service | [API.md](API.md) |

---

## 1. The problem

The same human is currently two people. Estiva Peek mints a custodied keypair
per account and publishes a name for it; Linear-lite generates a throwaway key
per browser and publishes its own. Nothing connects them, so a person who files
an issue and comments on it appears twice, under two pubkeys, with two profiles.

Stage 0 closed the rendering half — Linear-lite reads `kind:0`, so Peek's people
render as people. What remains is that **the two keys are still two identities**.

The goal: one person, one pubkey, one profile, reached by logging in once with a
passkey.

## 2. Three concerns, kept apart

This is the load-bearing split. Collapsing any two of these is how the design
goes wrong.

| Concern | Owner | Why there |
| --- | --- | --- |
| **Key** — who can sign | Estiva ID (custodial, for now) | One custodian instead of one per app is what makes one pubkey possible at all |
| **Admission** — who is in the workspace | Buzz relay, `admittedMembers` | Already built and formally verified (`Inv_AdmissionFence`). Revoking it is the offboarding lever, and it works regardless of who holds keys |
| **Attestation** — the `nip05` handle | Estiva ID, org-revocable | The org's badge. A leaver keeps a keypair; they lose the handle and the door |

Why it matters that these are separate: **a leaver keeps their keypair.** You
cannot take a private key back. What you can take back is admission (the relay
stops accepting them) and attestation (the handle stops resolving). If identity
were only "who holds a key", offboarding would be impossible. Because admission
lives at the relay and attestation lives here, offboarding is two revocations
neither of which requires cooperation from the person leaving.

## 3. Why a separate repo and a separate origin

Estiva ID is one of a suite — Estiva Peek (comms), Estiva Projects, Estiva
Notes, Estiva ID. Branded together, architecturally independent, and **the
second half of that sentence is the one that needs defending**.

Shared branding makes the pull towards a shared package, a shared component
library, or a shared database much stronger than it was when these looked like
strangers' apps. The moment any of that happens, "apps sharing no code and no
database work on the same data" stops being true, and the thing this ecosystem
is arguing gets quietly lost.

The two-layer story to hold onto: **Buzz is the neutral protocol layer; Estiva
is the vendor suite on top of it.** The suite interoperates through published
events and manifests, exactly as a third party's app would. That is the
commercial claim, and it is stronger than the research-demo version.

Concretely, in this repo: NIP-01 event serialization is implemented *here*
(`src/nostr/event.ts`) rather than imported from Peek. The duplication is the
architecture. It is kept honest by a test that pins this implementation's event
ids to the ones **Buzz's own Rust crates** produced — independence without
divergence.

**Not Convex**, deliberately: this service must outlive the other apps and
publish JWKS, which Convex is awkward at.

## 4. The `/sign` seam, and why not NIP-46

An app posts an unsigned event with the user's token and gets it back signed. No
app ever holds a secret key.

This is NIP-46's property — remote signing, secrets never leaving the signer —
over HTTPS instead of relay transport. Real NIP-46 is the wrong fit here:

* It needs a **socket** for `kind:24133` traffic. Convex functions are
  request-scoped and cannot hold one; `convex/nostr/sync.ts` already polls for
  exactly that reason.
* Signing latency measured in seconds would be unusable on every click.

**This is the seam Stage 4 re-points at a local signer**, so the
request/response contract matters more than what is behind it today. Keep it
clean; resist adding convenience to it.

### What `/sign` will not do

`/sign` as originally specced is a rubber stamp: hand it anything, get it back
signed as the user. A stolen browser token could then rewrite that person's
profile, delete their posts, or mint a NIP-98 credential to read the relay
directly, bypassing the apps.

So policy is attached to the **app**, and the token is audience-bound to one app
(`aud` = `client_id`). Two rules matter more than the exact kind lists:

1. **No app may sign `kind:0`.** The identity service owns profiles; an app that
   can publish one can undo that ownership. This is checked *before* the per-app
   allowlist, so it cannot be granted by editing a database row — the row being
   precisely what an attacker with database access would edit.
2. **NIP-98 (`27235`) is constrained by URL**, to the relay bridge only.
   Otherwise the endpoint mints HTTP credentials for arbitrary destinations.

Because the token names its app, a token lifted out of Linear-lite cannot be
replayed against Peek's different kind list.

Every grant and every refusal is written to `audit_events`.

## 5. Tokens

ES256 JWTs, with:

* `sub` = the user's **pubkey**. This is the point: Convex surfaces
  `getUserIdentity().subject`, so an app knows who signed an event without
  asking this service anything.
* `aud` = the app's `client_id`, which selects the signing policy.
* `iss` = this service's origin, from which `/.well-known/jwks.json` is
  discoverable in the standard way — the same path a Clerk or Auth0 integration
  takes.

The signing key is persisted and its private half is sealed in the same envelope
as user keys, so a database dump permits neither signing nor token forgery.

## 6. Why custody is accepted in Stage 1

Estiva ID holds every user's secret key, encrypted at rest. That means **the
service can sign as anyone.**

This is a deliberate trade, not an oversight:

* It is what makes `/sign` possible at all, and therefore what makes one pubkey
  across apps possible.
* It is what makes account recovery possible. Nobody can recover a lost
  non-custodial identity, which is why **escrow has to exist before custody
  goes**.

Two consequences that are decisions, not bugs:

* **Nothing signed here may be presented to users as cryptographic proof of
  authorship.** A signature proves the event came from this service, not from
  the person.
* **Stage 1 relay data is, in that sense, throwaway.** When identity moves to
  user-held keys, everything signed under custodied keys becomes unverifiable as
  personal authorship.

The argument for accepting custody is not that misuse will not happen but that
**it cannot happen unseen** — which is why the audit log is Stage 1 and not
later.

### Accepted for internal use

Three decisions taken on the basis that this is an internal deployment first.
All three need revisiting for real production use.

* **Offboarding does not propagate to Estiva Peek immediately.** Convex
  validates JWTs statelessly against JWKS, so a leaver holding a live token
  keeps their Peek session until it expires. The relay side is instant; the app
  side is not. Mitigation stays cheap — TTL plus refresh is a config value
  (`JWT_TTL_SECONDS`, currently 600s), not a rewrite.
* **Estiva ID is a single point of failure.** After Stage 2 no app can sign
  locally, so if this is down, nobody can publish anywhere. Worth getting right
  now: failure must be **loud**. Linear-lite already surfaces publish failures
  in its banner; Peek's relay publishes only `console.warn`, so an outage there
  looks like nothing happening.
* **Custody is still custody**, as above.

## 7. What Stage 4 changes, and what it costs

Stage 4 is passkey-PRF non-custodial keys, org escrow, and client-side signing.
It is not scoped here; only the storage *format* is fixed now
([KEY-CUSTODY.md](KEY-CUSTODY.md)).

**What it buys:** signatures become real evidence of authorship, and a server
breach yields ciphertext rather than every identity.

**What it costs:** Peek's backend can no longer sign, so publishing moves into
the browser — and nobody can recover a lost identity, so escrow has to exist
first.

Note the separation that makes Stage 1 shippable: **the passkey here is an
authenticator, not a key-wrapper.** Wrapping the Nostr key with passkey-PRF is
Stage 4. Conflating the two would force client-side signing now.

## 8. Deliberately not built yet

Admin UI, **any** user interface at all, the private directory, Blossom
avatars, invites, role and service identities, any call to Buzz's admission
API, and recovery flows.

Two entries left this list on 2026-08-07 (PEEK-31):

* **The `kind:0` publisher** is built — `src/domain/profile.ts` signs with the
  custodied key through `withUserSecretKey` and publishes over the relay's
  `POST /events` bridge. Estiva ID is now the sole writer; Peek's publisher is
  removed and Ship's is blocked on PEEK-48.
* **Profile editing** exists as an API — `GET`/`PUT /me/profile`. There is no
  screen; this service still serves no HTML, and PEEK-68 is where that changes.

`nostr.json` serving is off this list for a different reason: it is not ours to
build. The relay serves it per workspace, and Estiva ID stays authoritative by
publishing the profile the handle rides in.

Offboarding is partly built: `/sign` and `/token` refuse a person who is not
`active`, and revoking a handle works by republishing a `kind:0` without it.
The one-action admin operation (PEEK-66) is not built.

The two design questions that were held open — the domain layout for `nip05`
(PEEK-33) and who drives community admission (PEEK-36) — were **decided on
2026-08-04**, after this service was built and without changing any of it. The
decisions, the reasoning and what remains to implement are in
[OPEN-SEAMS.md](OPEN-SEAMS.md). In short: the relay serves `nostr.json` per
workspace while Estiva ID stays authoritative as the sole publisher of `kind:0`;
and Estiva ID observes admission rather than driving it, so a half-offboarded
person is visible rather than silent.

**Multi-workspace is the product goal, and Stage 1 is single-workspace only.**
Each customer gets their own community host and therefore their own handle
domain (`jan@abc.estiva.app`); Buzz is built for this, resolving the community
per request from the `Host` header. Authentication stays centralised at one
origin, so a contractor at two client companies remains one person with one
pubkey — though Buzz is explicit that profiles do not inherit across community
domains (`BUZZ_PROTOCOL_MODEL.md:350`), so that pubkey reposts its profile in
each. Shared deployment now, dedicated per-workspace deployments later; the
invariant that keeps the second cheap is that **a pubkey must survive the
split**. See [OPEN-SEAMS.md](OPEN-SEAMS.md).
