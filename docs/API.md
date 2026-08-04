# API

Every error shares one shape, with a stable machine-readable `code`:

```json
{ "error": { "code": "policy_violation", "message": "…", "detail": { "reason": "kind_not_allowed" } } }
```

| `code` | HTTP |
| --- | --- |
| `bad_request` | 400 |
| `unauthenticated` | 401 |
| `forbidden` | 403 |
| `not_found` | 404 |
| `conflict` | 409 |
| `policy_violation` | 422 |
| `internal` | 500 |

Two authentication modes:

* **Session cookie** (`estiva_id_session`) — for browsers on this origin.
* **Bearer JWT** — for apps on other origins. This is what `/sign` takes.

---

## Health

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/healthz` | Liveness. Never touches the database, so a Postgres outage does not get the container restarted. |
| `GET` | `/readyz` | Readiness. Does a DB round-trip; `503` when unreachable. |

## Passkeys

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `POST` | `/auth/register/options` | — | Body `{ email, displayName? }`. Creates the user and mints their key. `409` if the email already has a passkey. |
| `POST` | `/auth/register/verify` | — | Body is the WebAuthn attestation response. Sets the session cookie. |
| `POST` | `/auth/login/options` | — | Usernameless: no `allowCredentials`. |
| `POST` | `/auth/login/verify` | — | Body is the WebAuthn assertion. Sets the session cookie. |
| `POST` | `/auth/credentials/options` | Session | Enrol **another** passkey on an existing account. Verify with `/auth/register/verify`. |
| `POST` | `/auth/logout` | Session | Revokes the session. |
| `GET` | `/me` | Session | `{ id, email, displayName, status, pubkey }`. |
| `GET` | `/me/credentials` | Session | Summaries only — no public keys, no raw credential ids. |
| `DELETE` | `/me/credentials/:id` | Session | `404` if not yours. `409` if it is your only passkey. |

Challenges are single-use and expire in 5 minutes.

## Tokens and discovery

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | — | Discovery. |
| `GET` | `/.well-known/jwks.json` | — | Active key plus any `previous` one. |
| `POST` | `/token` | Session | Body `{ clientId }`. Returns an audience-bound JWT. |

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 600, "pubkey": "…", "issuer": "…" }
```

Claims: `iss` = issuer origin, `sub` = **the user's pubkey**, `aud` = the app's
`client_id`. ES256.

A relying party configures itself with the issuer URL and its `applicationID`,
and resolves JWKS through discovery — the same flow as a Clerk or Auth0
integration. For Convex that is `domain` + `applicationID` in
`convex/auth.config.ts`, and `getUserIdentity().subject` is then the pubkey.

## Signing

### `POST /sign`

Bearer JWT.

```json
{ "event": { "kind": 9, "created_at": 1753300200, "tags": [["h", "…"]], "content": "hello" } }
```

`created_at` defaults to now. **`pubkey` is accepted and ignored** — the server
always signs as the authenticated user, and recomputes the event id itself. A
caller does not choose whose signature it gets.

```json
{ "event": { "id": "…", "pubkey": "…", "kind": 9, "created_at": …, "tags": […], "content": "…", "sig": "…" } }
```

Refusals (`422`, `detail.reason`):

| `reason` | Meaning |
| --- | --- |
| `app_disabled` | The app credential is disabled. |
| `kind_profile_forbidden` | `kind:0`. Refused for every app, always — the identity service owns profiles. |
| `kind_not_allowed` | Outside this app's `allowed_kinds`. |
| `nip98_missing_url` | A `27235` event with no `u` tag. |
| `nip98_url_not_allowed` | The `u` URL is not allowed by both the deployment allowlist and the app's. |

`403` for an unknown app credential or an identity with no active key; `401` for
a missing or invalid token.

Grants and refusals are both written to `audit_events`. Event content is not.

### Policy

Per-app rows in `app_credentials`:

| App | `client_id` | Kinds |
| --- | --- | --- |
| Estiva Peek | `estiva-peek` | 9, 7, 5, 9007 |
| Estiva Projects (linear-lite) | `linear-lite` | 30850, 30851, 1851, 9, 5, 31989 |

NIP-98 URLs must be allowed by **both** `SIGN_NIP98_ALLOWED_URL_PREFIXES` (the
deployment's outer bound) and the app's `nip98_url_prefixes`. Both default to
empty, so `27235` signing is off until the relay bridge host is settled — see
[OPEN-SEAMS.md](OPEN-SEAMS.md).
