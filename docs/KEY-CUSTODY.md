# Key custody and the storage format

Implementation: [`src/crypto/envelope.ts`](../src/crypto/envelope.ts),
[`src/domain/keys.ts`](../src/domain/keys.ts).

Stage 1 ships a single deployment key. **The format is designed for M-of-N
escrow now**, because that is a format decision rather than a feature, and
retrofitting it later is a migration over every key in the table.

## The envelope

Two layers, always:

1. The secret is encrypted once under a **random per-secret DEK** (AES-256-GCM).
2. The DEK is distributed as one or more **shares**, each encrypted under a
   key-encryption key identified by `kid`.

```json
{
  "v": 1,
  "cipher": "AES-256-GCM",
  "iv": "…",
  "ct": "…",
  "aad": { "userId": "…", "pubkey": "…" },
  "dek": {
    "scheme": "direct",
    "threshold": 1,
    "shares": [
      { "kid": "deploy-1", "alg": "AES-256-GCM", "salt": "…", "iv": "…", "ct": "…" }
    ]
  },
  "createdAt": "2026-08-04T…"
}
```

The wrapping key for each share is `HKDF-SHA256(kek, salt, "estiva-id/envelope/kek-wrap/v1")`.

## Why two layers

Wrapping the secret *directly* under the deployment key — which is what Estiva
Peek's `convex/nostr/keys.ts` does today — has two problems that only show up
later:

* Every future custody change re-encrypts every secret.
* There is nowhere to put a second custodian.

With the DEK layer, adding a custodian rewrites a small JSON field. The
ciphertext is untouched. There is a test asserting exactly that: after adding a
second share, `ct` and `iv` are byte-identical and the secret still decrypts.

Peek's version also derives its key as `sha256(passphrase)` with **no key id**,
so there is no way to tell which key an existing row was wrapped under. This
format records `kid` per share, which is what makes rotation and escrow
expressible at all.

## Why `scheme` and `threshold`, not just a list of wraps

N independent wraps of the same DEK is **1-of-N**: *any single* holder can
decrypt. That is the opposite of escrow.

Real M-of-N needs the DEK split into shares that must be recombined. So the
format carries `scheme` and `threshold` from v1:

* `scheme: "direct"`, `threshold: 1` — one share carrying the whole DEK. Stage 1.
* `scheme: "shamir"`, `threshold: M` — Shamir shares; M of N reconstruct the DEK.
  Reserved for Stage 4.

`openEnvelope` **refuses** `shamir` today rather than guessing at a combiner that
does not exist yet. Failing loudly beats a plausible-looking wrong answer about
who can decrypt what.

## AAD binding

`aad` binds the ciphertext to the row that owns it, and is supplied by the caller
from the row it read — never taken from the envelope itself, since an attacker
who can move the envelope can move its `aad` too.

The property this buys, which matters *because* the service is custodial: moving
one user's envelope onto another user's row makes decryption **fail**, rather
than silently signing as the wrong person. Tested in
[`src/domain/keys.test.ts`](../src/domain/keys.test.ts).

## What "a database dump alone does not yield signing keys" does and does not mean

**Does:** the KEK lives in the environment (`KEY_ENCRYPTION_KEK`) and never in
Postgres. Someone with a dump — a backup, a stolen replica, a leaked snapshot —
has ciphertext and nothing else. There is a test that takes the real row and
fails to decrypt it with an attacker-chosen key.

**Does not:** a dump *plus* the environment is sufficient. Stage 1 is software-
only custody with no KMS or HSM. That is inherent to the stage, not a defect,
and it is why the `shares` list exists: a KMS-backed wrap can be added later
without re-encrypting anything.

## Operational notes

* `KEY_ENCRYPTION_KEK` is 32 bytes hex — `openssl rand -hex 32`.
* `KEY_ENCRYPTION_KID` names it. **Change the kid whenever you change the key**,
  or existing rows become undecryptable with no diagnostic.
* `resolveKek` returns `undefined` for unknown ids rather than falling back to
  the current key: an envelope wrapped under a retired key must fail loudly, not
  decrypt under the wrong one.
* `keyCustodyReport()` reports which kids currently hold custody, without
  exposing key material — the query to run before and after a rotation.

## Extracting a customer to their own deployment

The long-term product goal is dedicated per-workspace deployments (see
[OPEN-SEAMS.md](OPEN-SEAMS.md)). The same two-layer split makes that a data move
rather than a re-encryption:

1. Add a wrap under the new deployment's KEK to each affected envelope.
2. Ship the rows across.
3. Drop the old wrap.

**No user secret is re-encrypted, and no pubkey changes** — which is the
invariant that matters, because a changed pubkey detaches a person from
everything they ever signed. The mechanism designed for escrow serves tenant
extraction unmodified.

## Rotating the KEK (not yet implemented)

The format supports it; the procedure does not exist yet. It would be: add a
share under the new kid to every active envelope, verify the count with
`keyCustodyReport()`, then drop the old share. Because only the DEK wrap
changes, no user secret is re-encrypted and no signature is affected.
