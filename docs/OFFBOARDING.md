# Offboarding — the runbook

Who does which half, and what to check afterwards (PEEK-35, PEEK-66, PEEK-94,
PEEK-102).

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

### 1. The button — all four steps

Admin console → **Everyone** → open the person → **Offboard this person**.

In one action it revokes every passkey, disables the account and kills every
session, withdraws the handle by republishing a `kind:0` without `nip05`, and
**revokes their admission at the relay**.

The fourth step used to be a command printed for a human (PEEK-94 closed it).
Until somebody ran it, a leaver kept reading and writing on the relay with the
key they still held — the exact failure this page exists to prevent, reduced
from silent to merely manual.

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

### 2. The relay — only if the console says it did not happen

Buzz still **owns** admission (PEEK-36). What changed is that it can be asked:
the relay has always accepted membership changes as signed `kind:9031` events
through the same bridge this service publishes `kind:0` to, so offboarding
publishes one signed by the workspace's operator identity. No new endpoint, and
no reaching into another service's database
([ARCHITECTURE.md](ARCHITECTURE.md) §3).

When it worked, the console says so and **shows no command** — printing one
beside a step that already completed sends an admin to do something already done.

When it did not — no operator identity configured, the relay unreachable, the
operator not an admin there — the console shows the reason and the command, with
the pubkey already in it:

```bash
docker exec buzz-prod-relay-1 buzz-admin remove-member --pubkey <hex>
```

**Until that runs, the person can still read and write on the relay** using the
key they kept. Everything else is done and they still have the door.

Confirm either way:

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

## Do not offboard the relay operator

The identity named by `RELAY_OPERATOR_USER_ID` is what signs the membership
events above and what reads the roster. Offboarding it **revokes its own
admission**, so admission stops working for the whole workspace: every reading
degrades to "Not known", the people list goes grey, and offboarding silently
reverts to printing commands.

This happened on production during PEEK-94 QA — a cleanup script offboarded the
disposable identities and took the operator with them. Nothing said so, because a
grey column is also what "no operator configured" and "relay unreachable" look
like.

**The console now refuses it** (`400`, `reason: operator_identity`) and marks the
row *Relay operator*. To retire that identity, point `RELAY_OPERATOR_USER_ID` at
another one first, and admit the new pubkey at the relay as an admin:

```bash
docker exec buzz-prod-relay-1 buzz-admin add-member --role admin --pubkey <hex>
```

---

## Why the relay still owns the gate

Estiva ID drives admission but does not *decide* it. Buzz authorises every
`kind:9030`/`9031` in `relay_admin.rs` — sender must be `admin` or `owner`,
removals use an atomic conditional delete — and the membership fence itself is
fail-closed, checked at authentication time, and formally verified
(`Inv_AdmissionFence`). Adding a REST path beside that would mean two privileged
writes over one table, each carrying its own copy of those rules and drifting
apart quietly.

The asymmetry that shaped all of this:

* **Half-onboarded** — identity exists, never admitted. Annoying. They cannot
  publish and they say so on day one.
* **Half-offboarded** — removed here, still admitted there. A security problem,
  and a *silent* one.

Both are now visible rather than merely warned about: the console reads the
roster, so a mismatch is shown as a mismatch, and when admission cannot be read
at all the list says **which** of the four reasons applies instead of showing one
ambiguous grey chip.

---

## Restoring somebody

Admin console → open the person → **Reinstate this identity** (PEEK-102). It sets
the account back to `active` and **re-admits their pubkey at the relay** — both,
because a status change alone leaves them locked out there and looking fine here.

It does not give back:

* **Passkeys.** Offboarding revoked them because the devices left with the
  person. Issue a recovery link from the same page (PEEK-67); they enrol a new
  passkey and **keep the same key**, so nothing they signed detaches from them.
* **The handle.** It may have been taken since. They set it again from their own
  account page, which republishes properly.

Before this existed, undoing a mis-click meant `update users set status='active'`
against production plus a `buzz-admin add-member` — which is how the operator
incident above was actually recovered.

The audit log distinguishes the two directions: `user.reinstate` and
`user.status_change` record what the status changed *from*, which is what
separates restoring somebody's access from seizing their account. Those are
otherwise the same call.
