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
| `POST` | `/auth/register/options` | Invite | Body `{ inviteToken }`. Creates the user and mints their key. `403` without a valid invite; `409` if the email already has a passkey. |
| `POST` | `/auth/register/verify` | — | Body is the WebAuthn attestation response. Sets the session cookie. |
| `POST` | `/auth/login/options` | — | Usernameless: no `allowCredentials`. |
| `POST` | `/auth/login/verify` | — | Body is the WebAuthn assertion. Sets the session cookie. |
| `POST` | `/auth/credentials/options` | Session | Enrol **another** passkey on an existing account. Verify with `/auth/register/verify`. |
| `POST` | `/auth/logout` | Session | Revokes the session. |
| `GET` | `/me` | Session | `{ id, email, displayName, status, role, pubkey }`. |
| `GET` | `/me/credentials` | Session | Summaries only — no public keys, no raw credential ids. |
| `DELETE` | `/me/credentials/:id` | Session | `404` if not yours. `409` if it is your only passkey. |

Challenges are single-use and expire in 5 minutes.

## Invites

Registration is **invite-only** (PEEK-65). No password is created or sent — the
link's only job is to authorise exactly one passkey enrolment.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `POST` | `/invites` | Session, **admin** | Body `{ email, displayName?, handle?, role? }`. Returns the link **once**. `409` if the email already exists. |
| `GET` | `/invites` | Session, **admin** | Outstanding invites. `started: true` means somebody opened the link and never finished. |
| `GET` | `/invites/:token` | — | Prefill for the enrolment screen. `404` for unknown, expired *and* consumed alike, so tokens cannot be probed. |

**There is no mailer.** Stage 1 is internal: the admin copies the link into a
DM. Same flow, no provider dependency.

**The invitee cannot choose their own email** — it comes from the invite. A link
that let you pick would be transferable to anyone.

An invite is hashed at rest, lives 7 days, and is **burned only once a passkey
exists**. Consuming it at the start would turn a dismissed browser prompt — the
most common way enrolment fails — into a support request; instead the same link
reopens onto the same half-made account.

### Bootstrapping

An invite needs an admin, and a fresh deployment has none. On the box:

```bash
cd /opt/estiva-id && docker compose run --rm -T \
  -e EMAIL=you@example.com -e ROLE=admin -e HANDLE=you \
  estiva-id node dist/admin/create-invite.js
```

Locally, `EMAIL=… ROLE=admin pnpm invite`.

The first invite **must** be `ROLE=admin`; a member invite into an empty
workspace produces somebody who can sign in and invite nobody.

Requiring shell access is the point. "First registration becomes admin" is a
race on a public origin, and a bootstrap token in the environment is the same
secret as SSH with an extra copy to leak.

**An identity is not relay access.** The relay runs closed, so a newly enrolled
person cannot publish their profile until an operator admits their pubkey —
Buzz owns admission and Estiva ID only observes it (PEEK-36).

## Profile

Estiva ID is the **sole publisher of `kind:0`** (PEEK-31). Apps do not get a way
in here — `/sign` refuses `kind:0` for every app, always, and this route reaches
the key through an internal path rather than through that endpoint.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/me/profile` | Session | `{ displayName, picture, handle, communityHost, nip05, pubkey }`. |
| `PUT` | `/me/profile` | Session | Partial update, then publish. `409` if the handle is taken; `403` once the identity is not `active`. |
| `PUT` | `/me/avatar` | Session | Raw image bytes. Uploads to the relay, stores the URL as `picture`, republishes. |

```json
{ "displayName": "Ada", "picture": "https://…/a.png", "handle": "ada" }
```

**An absent key leaves a field alone; an explicit `null` clears it.** That
distinction is deliberate — collapsing them would make an avatar edit silently
revoke someone's `nip05`.

`handle` is the local part only (`ada`), not the full `ada@estiva.estiva.app`.
The domain comes from `COMMUNITY_HOST` and is joined at publish time, because
Buzz *discards* a `kind:0` whose handle domain does not equal `communities.host`
rather than returning an error.

The response reports publishing separately from saving:

```json
{ "profile": { … }, "published": true, "eventId": "…" }
```

**A save that could not be published still succeeded.** Postgres is the record
and the relay is a projection of it, so a relay outage leaves `published: false`
with a `publishError` and the edit intact — it does not roll the edit back.

## The private directory

Two channels, keyed the same way (PEEK-30). A person's public face is a `kind:0`
on the relay — `display_name`, `picture`, `nip05` — readable by anyone, including
apps nobody here wrote. Their **email is not there and never will be**: a private
contact address on a shared relay is unretractable, and Nostr's slot for a public
identifier is `nip05`, not email.

So "show me a colleague's name, email and avatar" is answered from two places
joined on the pubkey. That split is why this exists next to the profile rather
than inside it.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `POST` | `/directory/lookup` | Bearer JWT | Body `{ pubkeys: string[] }`, at most 200. |
| `GET` | `/directory/:pubkey` | Bearer JWT | One person. `404` if nobody holds that key. |

```json
{ "contacts": [ { "pubkey": "…", "displayName": "Grace Hopper",
                  "email": "grace@…", "role": "member", "status": "active" } ] }
```

**Lookup, never listing.** There is no endpoint that returns everybody. A caller
has to know the pubkey it is asking about, which it does because it read it off
an event it could already see — so a token scoped to one app is not a way to
export the staff directory. That view exists for admins at `/admin/people`.

Unknown pubkeys are **absent from the result**, not returned as nulls. An
explicit "no such person" for every key an app has ever seen would make this a
way to test which keys are members.

**The caller must still be active.** Tokens live 600s and a leaver holds one
until it expires, so the subject is re-checked here — otherwise the directory
stays readable for ten minutes after an offboarding.

`status` is included so an app can tell a current colleague from a former one. A
leaver's name and email still resolve, because their old messages have to keep
rendering as written by a person.

Batch exists because the caller is an app rendering a thread with a dozen
authors, over a **preflighted cross-origin request**. A per-pubkey endpoint would
make the obvious implementation a dozen round trips, each with its own OPTIONS.

### Cross-origin

Both routes send CORS headers, from the same allowlist as `/token` — the
registered redirect URIs, so there is one list rather than two that drift. The
shared rules live in `src/http/cors.ts`.

**`Access-Control-Allow-Credentials` is never sent**, which is what keeps this
safe: a browser will not attach the session cookie cross-origin nor expose a
credentialed response, so cookie-authenticated routes stay same-origin-only while
this bearer-authenticated one works from anywhere registered.

In-process tests cannot verify any of that — nothing enforces CORS when a Hono
app is called in the same process, which is how PEEK-90 shipped green tests and
a feature that could not work. This is checked in a browser across two origins.

## The admin directory

Admin only, and read-only (PEEK-64). Nothing here writes; the mutations an admin
will want are their own tickets (PEEK-66 offboarding, PEEK-34 role identities),
and shipping them alongside the screen that first makes the state legible would
mean shipping them before anyone had looked at what the state is.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/admin/people` | Session, **admin** | Everyone with an account, plus invites nobody has opened. |
| `GET` | `/admin/people/:id` | Session, **admin** | One person plus their passkey summaries. `404` for an unknown id **and** for an invite id. |
| `GET` | `/admin/audit` | Session, **admin** | The audit trail. `?person=`, `?action=`, `?before=`, `?limit=`. |
| `POST` | `/admin/people/:id/offboard` | Session, **admin** | Offboard in one action. `409` if already offboarded; `400` on yourself. |

A stranger gets `401`, not `403` — a `403` would confirm the route exists to
somebody with no session. Status is checked before role, so an admin who has been
offboarded loses this immediately rather than when their session expires.

### Three dimensions, never collapsed

A person is not one status, and the whole value of the list is that these can
disagree:

| Field | Owner | Values |
| --- | --- | --- |
| `status` | this service | `active` · `suspended` · `offboarded` · `null` for an invite |
| `enrolment` | this service, derived | `invited` · `enrolling` · `enrolled` |
| `admission` | the Buzz relay | `admitted` · `not-admitted` · `unknown` |

`enrolling` is the expensive state: the invite was opened, a user row and a
custodied key exist, and the passkey prompt was dismissed. They own a pubkey and
cannot sign in, and nothing else in either system says so.

**`admission` is `unknown` today, always, and that is not a stub.** Buzz owns
admission and exposes no way to read it — the relay's HTTP surface has the
bridge, media, NIP-05 and a moderation API, and `buzz-admin list-members` is a
CLI against Buzz's own Postgres. Answering it would mean this service connecting
to another service's database, which is the coupling the suite exists to argue
against. So it is displayed as "not known" and never inferred as "probably
fine" — the one reading that would make a half-offboarded person look admitted.
The port is `src/domain/admission.ts`; a real implementation is a second class,
not a new seam.

An unopened invite appears on the list and is deliberately **not** addressable at
`/admin/people/:id`: there is no account to open, and everything known about it
is already on the row. Once somebody opens their link they have a user row, and
they stop appearing as an invite so nobody is listed twice.

### `PUT /me/avatar`

Raw bytes with the file's own `Content-Type` — not multipart. There is one file
and no other fields, so `body: file` in the browser is the whole request.

PNG, JPEG, WebP or GIF, up to 5 MB. **SVG is refused**: it is a document that can
carry script, and an avatar renders in every app in the suite.

```json
{ "profile": { … }, "avatar": { "url": "…", "sha256": "…", "size": 8134 },
  "published": true, "eventId": "…" }
```

The URL is content-addressed and served by the workspace's own relay, which is
the point — Stage 0 published a Convex storage URL, tying an ecosystem-wide
avatar to one deployment's lifetime.

**The upload must succeed before anything is written.** A `picture` pointing at
a blob that was never stored is a broken avatar in every app at once. After that
the usual split applies: the save is committed and `published` reports
separately, so a relay that takes the blob and refuses the event leaves the
avatar set rather than rolling it back.

Refusals worth distinguishing:

| Condition | Code | HTTP |
| --- | --- | --- |
| Not an allowed type, empty, or over 5 MB | `bad_request` | 400 |
| Identity not admitted to the relay | `forbidden`, `detail.reason = not_admitted` | 403 |
| Media store declined the file | `policy_violation` | 422 |
| Media store unreachable | `internal` | 500 |

`not_admitted` is called out on its own because it is the one an operator can fix
in a minute — the relay runs closed, and telling somebody "upload failed" when
the answer is "nobody has let you in yet" sends them to look at their file.

**This is Blossom BUD-11, not NIP-98.** The media store authenticates with a
signed `kind:24242` event: `t=upload`, an `x` tag matching the body's sha256, a
*required* `expiration` in the future, **non-empty `content`**, and a mandatory
`X-SHA-256` request header agreeing with the `x` tag. Buzz answers `401` for
anything wrong with that event and `403` only for membership, which is what lets
`scripts/probe-blossom.ts` verify the client against the live relay without
being admitted to it and without storing anything.

The upload is signed **here**, not in the browser: the key is custodied, and
minting a Blossom token through `/sign` is exactly the rubber stamp `/sign` was
constrained to refuse.

### `GET /admin/audit`

Written since the service was built, read by nobody until PEEK-69 — which left
"custody is acceptable because misuse cannot happen unseen" resting on a table
with no viewer.

```json
{ "entries": [ { "id": "42", "occurredAt": "…", "action": "user.status_change",
                 "outcome": "success",
                 "actorUserId": "…", "actorEmail": "admin@…", "actorClientId": null,
                 "subjectUserId": "…", "subjectEmail": "leaver@…",
                 "detail": { "from": "active", "to": "offboarded" } } ],
  "nextBefore": "37", "actions": ["invite.create", "…"] }
```

`?person=<user id>` returns **what that person did and what was done to them**.
Both directions, because "who offboarded this account" is the question a history
is opened to answer, and it is not something the account itself did.

The subject is resolved from `subject_pubkey` through `user_keys` — including
rotated keys, so a record written before a rotation still names the right
person.

**Paged by `id`, not by time.** A request writes several rows in the same
millisecond, so a timestamp cursor drops or repeats rows at a page boundary.
`nextBefore` is returned **only when the page came back full**; a short page is
the end.

Read-only, and there is no write surface at all — an audit log an admin can
edit answers a different question from the one it exists to answer.

**Retention is still unsolved.** Nothing prunes this table and nothing archives
it, so it grows forever and a restore brings all of it back. Fine at Stage 1
volumes; it needs a policy before it is not.

### `POST /admin/people/:id/offboard`

One action, because a partly-offboarded leaver is a security problem and a
manual checklist guarantees one eventually (PEEK-66). Revokes every passkey,
disables the account and kills its sessions, and withdraws the `nip05` handle by
republishing a `kind:0` without it.

```json
{ "passkeysRevoked": 1, "sessionsRevoked": 2, "handleRevoked": "leaver",
  "attestationPublished": true,
  "relayAdmission": { "revoked": false, "reason": "buzz_owns_admission",
                      "command": "docker exec buzz-prod-relay-1 buzz-admin remove-member --pubkey …" } }
```

**`relayAdmission.revoked` is always `false`, and that is not a bug.** Buzz owns
community admission and exposes no way to drive it, so this does three of the
four steps and hands back the command an operator still has to run. Reporting
success would convert a known manual step into an unknown one.

`attestationPublished: false` means the withdrawal did not reach the relay, so
**the handle still resolves** for anyone reading the old event. The local
revocations happen first precisely so a relay outage cannot leave a login
working.

The key is deliberately **left active** — revoking it would make everything the
person ever signed unattributable, and `/sign` refuses on `users.status` anyway
(PEEK-88).

An admin cannot offboard themselves: there is no recovery flow (PEEK-67), so it
is a mistake nobody undoes without shell access.

Full runbook, including the relay half: [OFFBOARDING.md](OFFBOARDING.md).

## Tokens and discovery

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | — | Discovery. |
| `GET` | `/.well-known/jwks.json` | — | Active key plus any `previous` one. |
| `GET` | `/authorize` | Session | Browser redirect. Issues an authorization code. |
| `POST` | `/token` | Session, code **or** client secret | Three grants — see below. |

### Three grants, and why each exists

**`authorization_code` with PKCE** is how an app on another origin gets a token.
It has to be a redirect flow: the session cookie is `SameSite=Lax` and this
service serves no CORS, so a cross-origin `fetch` carrying credentials is
blocked twice over. Neither is worth relaxing on the origin that holds every
custodied signing key.

**The session grant** stays because the account page is served from this very
origin, and making it round-trip through a redirect to reach its own backend
would be ceremony with nothing to show for it.

**`client_credentials`** is how a **role identity** signs (PEEK-34). A bot has
nobody to sign in, so before it existed a role could hold a custodied key it
could never use. A server-side app authenticates with its own secret and gets a
token for the identity it is registered to act as — no person anywhere in the
flow.

That secret **buys** a token rather than being one, so a bot is bounded by the
same `JWT_TTL_SECONDS` as everybody else and disabling it takes effect just as
fast. It makes such an app a *confidential* client, which browser apps are not
and must never be — a secret shipped in a bundle is public — so the grant
refuses any credential without a stored secret hash, and a database constraint
stops one being pointed at an identity without a secret. Peek and Ship are
public clients and stay that way.

The body selects the grant; there is one endpoint, which is what discovery
advertises — now as `["authorization_code", "client_credentials"]`.

### `GET /authorize`

```
/authorize?client_id=…&redirect_uri=…&response_type=code
          &code_challenge=…&code_challenge_method=S256&state=…
```

`code_challenge` is `base64url(sha256(code_verifier))` — 43 characters. **`S256`
only**; `plain` is refused, because it protects nothing an interceptor cannot
replay.

Failures split in two, deliberately:

* **An unknown `client_id` or an unregistered `redirect_uri` renders a `400`
  here and does not redirect.** Bouncing to an unvalidated URI is how an
  identity provider becomes an open redirector, and the payload is a code.
* **Anything after that goes back to the app** as `?error=…&state=…`, which is
  what OAuth clients read.

No session means a `302` to `/?next=<relative path>` so the person can sign in
and be replayed. Redirect URIs are matched **exactly**, never by prefix.

There is no consent screen: every app is first-party. That changes the day a
third-party app is registered.

### `POST /token`

```json
{ "grantType": "authorization_code", "code": "…", "clientId": "…",
  "redirectUri": "…", "codeVerifier": "…" }
```

or, from this origin with a session cookie:

```json
{ "clientId": "estiva-peek" }
```

or, as a role identity's custodian:

```json
{ "grantType": "client_credentials", "clientId": "…", "clientSecret": "…" }
```

All three return the same body. **Every `client_credentials` refusal is
`invalid_client`**, whether the client is unknown, the secret is wrong, the
client is public, or the identity has been offboarded — telling them apart would
make this endpoint an oracle for enumerating credentials. Which it was is in the
audit log. **Every code-grant refusal is `invalid_grant`** —
unknown, expired, replayed, wrong verifier and wrong redirect URI are one
answer to the caller and distinct reasons in `audit_events`. The distinction
matters to us; handing it to a redeemer is handing them a probe.

A code is single-use, lives 60 seconds, and is **burned on any redemption
attempt**, successful or not: one that has been presented has been in the wild.

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 600, "pubkey": "…", "issuer": "…" }
```

Claims: `iss` = issuer origin, `sub` = **the user's pubkey**, `aud` = the app's
`client_id`. RS256 — **not** ES256, because Convex rejects ES256 tokens with
`Could not verify OIDC token claim` even when they verify against our own JWKS
with a compliant library. See `src/domain/jwt.ts` for the full reasoning.

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

**Cross-origin**, from the same allowlist as `/token` and the directory — the
registered redirect URIs, with `Access-Control-Allow-Credentials` never sent
(`src/http/cors.ts`).

This was missing until PEEK-93, and the omission was total: no `OPTIONS`
handler, no header on the response. Ship's `estivaIdSigner` calls this from the
browser with a Bearer header, which is **preflighted**, so every signed action
failed with a generic network error and no status. A full passing suite said
nothing about it, because nothing enforces CORS when a Hono app is called
in-process.

**The header is set before any refusal can be thrown**, so a `policy_violation`
is readable by the app it refused. Otherwise "this app may not sign that kind"
reaches the caller as "network error", which defeats the point of the
`detail.reason` vocabulary below.

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
| Estiva Peek | `estiva-peek` | 9, 7, 5, 9007, 27235 |
| Estiva Ship | `estiva-ship` | 30850, 30851, 1851, 9, 5, 9007, 31989, 27235 |

**9007 is the container, not an afterthought.** Ship's Folder carries the `h`
tag every project, issue, change and message references, and `createProject`
publishes it *before* the Project — so omitting it left Ship able to add to a
folder somebody else made and unable to create its first one (PEEK-97). Listing
an app's object kinds without their container is not a lower ceiling, it is a
broken one. The same number is a huddle for Peek: this list says what an app may
sign, not what a kind means.

A **service credential** (PEEK-34) carries its own kinds the same way, set when
an admin mints it.

NIP-98 URLs must be allowed by **both** `SIGN_NIP98_ALLOWED_URL_PREFIXES` (the
deployment's outer bound) and the app's `nip98_url_prefixes`. Both default to
empty, so `27235` signing is off until the relay bridge host is settled — see
[OPEN-SEAMS.md](OPEN-SEAMS.md).
