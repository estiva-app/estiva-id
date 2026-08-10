# Offboarding — the runbook

Who does which half, and the one step a button cannot take (PEEK-35, PEEK-66).

---

## The thing to understand first

**A leaver keeps their keypair.** That is inherent — no database write takes a
private key back, and Estiva ID holding a copy changes nothing about it. So
offboarding is never "delete the identity". It is withdrawing what the *org*
controls:

| | Withdrawn | Owner |
| --- | --- | --- |
| **The badge** | the `nip05` handle stops resolving | Estiva ID |
| **The door here** | login, tokens, signing | Estiva ID |
| **The door there** | the relay stops accepting their events | **Buzz** |

**Custody adds nothing to offboarding.** It works identically whether or not
this service holds the key — which is worth writing down, because it is what
makes non-custodial keys (Stage 4) viable for an organisation. The lever was
never the key.

Nothing they wrote is deleted or rewritten. Revocation removes what somebody can
do *next*; historical writes keep their community label and stay
(`buzz/docs/multi-tenant-relay.md:219`). The org keeps the record — that is the
point of having one.

---

## Doing it

### 1. The button — three of the four steps

Admin console → **Everyone** → open the person → **Offboard this person**.

In one action it revokes every passkey, disables the account and kills every
session, and withdraws the handle by republishing a `kind:0` without `nip05`.

One action rather than a checklist because **a partly-offboarded leaver is a
security problem**, and a manual sequence guarantees one eventually.

The local revocations happen first, deliberately: they are writes to our own
database and cannot fail. Republishing the profile is a network call to the
relay and can. Ordering it the other way round would let a relay outage leave
somebody's login working.

Effects here are immediate. **Estiva Peek is not**: it validates JWTs
statelessly against JWKS, so a leaver holding a live token keeps their Peek
session until it expires — at most `JWT_TTL_SECONDS`, currently 600. That window
is a config value, not a rewrite, and it is a known accepted cost
([OPEN-SEAMS.md](OPEN-SEAMS.md)).

### 2. The relay — the step the button cannot take

**Estiva ID cannot revoke community admission.** Buzz owns it (PEEK-36) and
exposes no HTTP surface for it at all: `buzz-admin` is a CLI against Buzz's own
Postgres, and reaching into another service's database is the coupling this
suite exists to refuse ([ARCHITECTURE.md](ARCHITECTURE.md) §3).

So the console shows the command, with the pubkey already in it. On the box:

```bash
docker exec buzz-prod-relay-1 buzz-admin remove-member --pubkey <hex>
```

**Until that runs, the person can still read and write on the relay** using the
key they kept. Everything else is done and they still have the door.

Confirm it took:

```bash
docker exec buzz-prod-relay-1 buzz-admin list-members
```

### 3. Check the handle actually stopped resolving

The withdrawal only means anything once the relay has the new profile. If the
console reported that the publish failed, the old event still carries the
handle:

```bash
curl "https://estiva.estiva.app/.well-known/nostr.json?name=<handle>"
```

An empty `names` object is what you want. If the handle is still there, the
republish did not land — fix the relay and save the person's profile again.

---

## Why it is not one button

It should be, and the intended end state still is. Estiva ID *observes*
admission rather than driving it because Buzz's gate is the right place for it —
fail-closed, checked at authentication time, and formally verified
(`Inv_AdmissionFence`). Taking a write dependency on Buzz's control plane to save
one command would put the fence's correctness partly in this service's hands.

What made that trade acceptable is that the dangerous half is the one we closed:

* **Half-onboarded** — identity exists, never admitted. Annoying. They cannot
  publish and they say so on day one.
* **Half-offboarded** — removed here, still admitted there. A security problem,
  and a *silent* one.

The console is built so the second cannot be silent: the person's row keeps
showing the outstanding relay step after a reload, and the audit record says
`relayAdmissionRevoked: false`. It is a manual step that is **visible**, rather
than a manual step somebody forgot.

**Relay admission cannot be read back either** — there is no membership read
endpoint, so the console shows "Relay: Not known" rather than guessing. Giving
Buzz one would let this page show the mismatch instead of merely warning about
it, and is the single change that would most improve this runbook.

---

## Restoring somebody

There is no "undo". Setting a person back to `active` re-enables login and
tokens, but their passkeys stay revoked and there is **no admin-assisted
recovery** (PEEK-67) — they need a fresh invite, and re-admitting them at the
relay is `buzz-admin add-member`.

The audit log distinguishes the two directions: `user.status_change` records
what the status changed *from*, which is what separates restoring somebody's
access from seizing their account. Those are otherwise the same call.
