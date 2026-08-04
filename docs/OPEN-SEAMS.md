# Seams — what is decided, and what is still open

Two questions were deliberately left open while the service was built. **Both
are now decided** (2026-08-04). This page records the decisions, why they were
made, and what remains to implement — followed by the smaller things still open.

---

## DECIDED · Domain layout and `nip05` (PEEK-33)

**Decision: serve `/.well-known/nostr.json` from Estiva ID, exposed at the
community domain by routing that single path to it.**

### The constraint

A `nip05` handle is a name that maps to a pubkey — `jan@estiva.app` rather than
`714902a6…`. It resolves by fetching
`https://<domain>/.well-known/nostr.json?name=jan`. There is no registry:
**whoever controls the domain controls what the handle means.** That is why the
handle is the org's *attestation* — the badge saying this pubkey is our person —
and why revoking it is deleting a line from a file.

Buzz requires the handle's domain to match the **community's** domain.
Off-domain or invalid handles are *silently cleared*
(`BUZZ_PROTOCOL_MODEL.md:235`) — they do not error, they vanish, which is a
miserable thing to debug.

That splits knowing from serving: Estiva ID holds the handles; the community
domain must answer for them.

### Why this option

The alternative — the relay serving `nostr.json`, fed from here — makes
revocation a *distributed* operation. Estiva ID deletes a handle and the relay
keeps serving it until something syncs, leaving a window where a leaver's badge
still resolves. That trades away the one property most worth protecting.

Routing a single path keeps revocation **local and immediate**: delete the row,
the next request reflects it. One system owns the badge end to end, matching the
key / admission / attestation split. And it does not consume the apex, so the
marketing site keeps it.

### What this requires operationally

**One reverse-proxy rule, outside this repo**, at the community domain:

```
/.well-known/nostr.json  →  <estiva-id origin>/.well-known/nostr.json
```

A Vercel rewrite, a Cloudflare rule, or an nginx `location` block — whatever
fronts the apex. Everything else at that domain is unaffected.

**This is the fragile part of the decision.** It is infrastructure config that
lives in no repository, so it is invisible until handles quietly stop resolving.
Whoever sets it up should record where it lives. Treat it as part of the
deployment, not as a one-off.

### Still to implement

* `GET /.well-known/nostr.json?name=<handle>` in this service.
* A handles table, unique per handle, revocable independently of the account —
  offboarding revokes the handle without deleting the identity.
* CORS: `Access-Control-Allow-Origin: *`. NIP-05 lookups are cross-origin by
  nature and fail silently without it.
* `NIP05_DOMAIN` config, which **must equal** Buzz's configured community
  domain. A mismatch is the silent-clearing failure above.

### Consequence to act on now

`RP_ID` and `ISSUER_URL` follow from this. Passkeys are cryptographically bound
to a domain: one enrolled against `id.estiva.app` **will not work** at
`estiva.app`, with no migration path — everyone re-enrols. Settle the final
hostnames before anyone real enrols, and set `RP_ID` once.

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

### Still to implement

Nothing yet — there is no consumer until the admin surface exists, and building
the port before then would be a speculative abstraction. When the people list is
built, it needs:

* A read-only admission port: `getAdmissionStatus(pubkey) → admitted | not-admitted | unknown`.
* `unknown` as an honest state, shown as such. Never inferred as "probably fine".
* Per-person display of identity **and** admission, so a mismatch is visible
  without anyone going looking.

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
* **The audit log is written but never read.** No query surface, no retention
  policy.
* **Multi-community.** One workspace is assumed throughout; see
  [ARCHITECTURE.md](ARCHITECTURE.md) §8.
