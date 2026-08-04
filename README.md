# Estiva ID

Passkey-backed identity, key custody and remote signing for the Estiva suite —
one human, one pubkey, one profile, across every app.

Standalone by design: its own repo, its own origin, its own database. Node +
Hono + Postgres, deliberately not Convex (it must outlive the other apps and
publish JWKS).

**Stage 1 is custodial on purpose.** This service holds every user's secret key,
encrypted at rest, which means it *can* sign as anyone. Nothing signed here may
be presented to users as cryptographic proof of authorship until Stage 4 moves
keys out of custody. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §6.

## Start here

| If you want to… | Read |
| --- | --- |
| **Understand the design without re-deriving it** | **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** |
| Know what is deliberately undecided | [docs/OPEN-SEAMS.md](docs/OPEN-SEAMS.md) |
| Understand the at-rest key format | [docs/KEY-CUSTODY.md](docs/KEY-CUSTODY.md) |
| Call the service | [docs/API.md](docs/API.md) |

## Running it

Needs Node ≥ 22.12, pnpm and Docker.

```bash
pnpm install
cp .env.example .env
```

Put a real key-encryption key in `.env` — the service refuses to start without
one, because silently defaulting it would be worse than failing:

```bash
sed -i "s/^KEY_ENCRYPTION_KEK=.*/KEY_ENCRYPTION_KEK=$(openssl rand -hex 32)/" .env
```

Then:

```bash
pnpm db:up && pnpm migrate && pnpm seed && pnpm dev
```

`pnpm seed` inserts the two app credentials with their signing policies.

```bash
curl -s localhost:8787/readyz
```

## Working on it

```bash
pnpm test
```

```bash
pnpm lint:fix && pnpm typecheck && pnpm test
```

Tests run against a real Postgres rather than mocks — the things worth testing
here are transactional and constraint-shaped, and a fake would only confirm the
fake. WebAuthn is exercised through real ceremonies using a software
authenticator (`src/test/authenticator.ts`) that emits genuine CBOR attestation
objects, COSE keys and DER signatures.

## Layout

| Path | What |
| --- | --- |
| `migrations/` | Plain SQL, applied in order, checksummed |
| `src/config.ts` | Zod-validated env; throws before the server binds |
| `src/crypto/envelope.ts` | The at-rest encryption format — escrow-ready |
| `src/nostr/` | NIP-01 events and schnorr signing, implemented locally on purpose |
| `src/domain/` | Users, keys, credentials, sessions, policy, tokens, audit |
| `src/http/routes/` | `auth`, `sign`, `tokens` |

## Two things not to break

**Event ids are pinned to Buzz's Rust.** `src/nostr/event.test.ts` asserts this
implementation reproduces an id `buzz_sdk::builders::build_message` produced. The
duplication with Peek's copy is the architecture — apps in this ecosystem are
independent implementations, not siblings sharing a package — and that test is
what keeps independence from becoming divergence. A failure means the two have
drifted; do not update the expected id.

**`kind:0` is refused for every app, before the per-app allowlist is consulted.**
The identity service is the sole publisher of profiles. An app that can publish
one can undo that ownership, and the check is ordered so it cannot be granted by
editing a database row.
