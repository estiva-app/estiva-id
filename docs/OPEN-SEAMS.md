# Open seams — decisions this code deliberately does not make

Two design questions are unresolved. Neither is baked into the implementation.
Where the code had to do *something*, it does the fail-closed thing and exposes
a configuration point.

**If you are about to hardcode either of these, read the relevant section
first.** Both were left open on purpose, and both are cheap now and expensive
later.

---

## 1. Domain layout and `nip05` (PEEK-33)

**The question.** Buzz canonicalises NIP-05 handles to the *community* domain
(`BUZZ_PROTOCOL_MODEL.md:235`) — off-domain or invalid handles are silently
cleared. So `/.well-known/nostr.json` has to resolve on the **relay's** domain,
not the identity service's. Two options:

1. Identity service at the apex, relay on a subdomain.
2. Relay serves `nostr.json`, fed from the identity service.

This is not a DNS chore. The handle is the **org's revocable attestation** — the
badge that says this pubkey is our employee — and whoever serves it owns the
revocation path.

**What this repo does instead.** Nothing is served at `/.well-known/nostr.json`.
There is no placeholder handler, because a placeholder that returns an empty
object is indistinguishable from a broken one.

**What it touches, and the cost of leaving it open:**

* `RP_ID` / `RP_ORIGINS` — WebAuthn is origin-bound. **Changing `RP_ID` after
  people have enrolled invalidates every passkey.** This is the real cost of the
  delay: every day of enrolment before the decision is a day of re-enrolment
  after it, if the answer moves the origin.
* `ISSUER_URL` — appears in every token and in discovery. Changing it invalidates
  live tokens and requires relying parties to be reconfigured.
* `SIGN_NIP98_ALLOWED_URL_PREFIXES` — the relay bridge's host follows from this
  decision. It **defaults to empty, which refuses all kind 27235 signing**.
  Fail-closed, matching Buzz's own posture on `pubkey_allowlist`.

**When it must be decided:** before `nip05` work starts, and ideally before
anyone enrols a passkey against a hostname you intend to change.

---

## 2. Who drives community admission (PEEK-36)

**The question, and the largest unresolved one in the project.** Onboarding is
two operations: create an identity here, and admit the pubkey to the Buzz
community. Buzz's control plane owns the second (`AddMembership` /
`RevokeMember`, driven today from `admin-web`).

1. **Estiva ID calls Buzz's admission API.** One onboarding action, one place to
   offboard. Couples this service to Buzz's control plane.
2. **Two-system dance.** Create the identity here, admit separately in
   `admin-web`. Honest separation, more room for someone to exist with no
   access, or keep access after leaving.

Option 2's failure mode is the one that matters: an identity that was never
admitted looks broken, and a leaver who was only half-offboarded is a security
problem.

It decides whether "add a person" and "offboard a person" are complete actions
or three-quarter ones — and both admin surfaces are built on the answer.

**What this repo does instead.** There is no admission call and no admission
client. `users.status` (`active` / `suspended` / `offboarded`) exists and is
enforced at login, but it describes only *this service's* view. It deliberately
does **not** claim to represent relay admission, because that would be a lie in
option 2 and redundant in option 1.

**When it must be decided:** before the admin surface is built. Deciding it late
is expensive because both onboarding and offboarding UI encode the answer.

---

## Smaller things left open

* **Recovery.** There is no account-recovery path. Enrolling a second passkey
  requires an existing session, which you cannot get on a new device if you lost
  the only one. Cross-device enrolment normally happens client-side via WebAuthn
  hybrid transport (the QR flow), so the server seam is right — but "I lost my
  laptop" has no server-side answer in Stage 1. Revoking your last passkey is
  refused for this reason.
* **Registration is open.** Anyone who can reach the origin can create an
  account. Invite-gated enrolment is PEEK-65.
* **KEK rotation** is expressible in the format but has no procedure —
  see [KEY-CUSTODY.md](KEY-CUSTODY.md).
* **The audit log is written but never read.** No query surface, no retention
  policy.
* **Multi-community.** Assumed one workspace throughout; see
  [ARCHITECTURE.md](ARCHITECTURE.md) §8.
