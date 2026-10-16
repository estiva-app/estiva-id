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
  A person's session ends 7 days after its last use or 14 days after the
  passkey tap, whichever is first (`SESSION_IDLE_SECONDS`,
  `SESSION_MAX_SECONDS`). A use is a request with the cookie or a renewal at
  `/token`. The cookie is set once, at the tap, to the 14-day end: a renewal
  never carries it, so the idle end lives on the session row. A bot's
  delegated session keeps a fixed 24 hours and has no idle end.
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
| `POST` | `/auth/logout` | Session | Revokes the session. Same-origin only — see `GET /logout` for apps. |
| `GET` | `/me` | Session | `{ id, email, displayName, status, role, pubkey }`. |
| `GET` | `/me/credentials` | Session | Summaries only — no public keys, no raw credential ids. |
| `DELETE` | `/me/credentials/:id` | Session | `404` if not yours. `409` if it is your only passkey. |
| `POST` | `/auth/reauth/options` | Session | Confirm it is still you: an assertion offered only your own passkeys. |
| `POST` | `/auth/reauth/verify` | Session | Body is the WebAuthn assertion. Moves this session's tap time; no new session, and its 14-day end stays. `401` for a passkey that is not yours. |

Challenges are single-use and expire in 5 minutes.

**Changing the account needs a recent tap** (AUT-2). More than 15 minutes
(`REAUTH_SECONDS`) after the session's last passkey tap, these answer `403`
with `detail.reason = reauth_required` and change nothing:
`/auth/credentials/options`, `DELETE /me/credentials/:id`,
`/me/sessions/revoke-others`, `POST /invites`,
`/admin/people/:id/recovery`, `/admin/people/:id/role`,
`POST /admin/role-identities`, `/admin/role-identities/:id/credential` and
`PATCH /admin/credentials/:clientId/kinds`. Confirm with
`/auth/reauth/options` → `/auth/reauth/verify`, then retry.

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

### Enrolment admits the pubkey

Onboarding is two operations against two systems: create the identity here, and
admit the pubkey to the Buzz community. Until PEEK-94 this service could only do
the first, so a colleague could open their link, enrol a passkey, sign in — and
read nothing in either app, because the relay runs closed and had never heard of
their key. "Add a person" was three-quarters of an action.

Finishing enrolment now publishes a `kind:9030` for the new pubkey, then the
reserved handle's `kind:0`. **That order is the contract**: a profile from a
pubkey the relay does not yet admit is dropped, which used to leave the handle
stored locally and resolving nowhere, waiting on an account-page save nobody
knew to make.

**A failure here does not fail enrolment.** The person already has a working
passkey and a session, and refusing would strand an account they can already
authenticate to. It is recorded as a `relay.admit` audit entry with
`outcome: error`, the row shows "Not admitted", and an admin completes it with
`POST /admin/people/:id/admit`.

Buzz still *owns* admission (PEEK-36). What changed is that the decision can be
asked for rather than printed as a command and hoped for.

## Profile

Estiva ID is the **sole publisher of `kind:0`** (PEEK-31). Apps do not get a way
in here — `/sign` refuses `kind:0` for every app, always, and this route reaches
the key through an internal path rather than through that endpoint.

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/me/profile` | Session | `{ displayName, picture, handle, communityHost, nip05, pubkey }`. |
| `PUT` | `/me/profile` | Session | Partial update, then publish. `409` if the handle is taken; `403` once the identity is not `active`. |
| `PUT` | `/me/avatar` | Session | Raw image bytes. Uploads to the relay, stores the URL as `picture`, republishes. |
| `GET` | `/avatar/:sha256.:ext` | **None** | The published `picture`. Streams the relay blob, signing the read. |

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

Admin only, and read-first (PEEK-64). The list, the person and the audit trail
were built before any write, so the screen that makes the state legible shipped
before anything that changes it.

The writes arrived as their own tickets, and each earned its place by being an
action whose absence sent somebody to a shell: offboarding (PEEK-66), role
identities (PEEK-34), and — after offboarding the relay operator on production
turned a mis-click into a hand-written `UPDATE` — reinstatement and by-hand
admission (PEEK-102, PEEK-65).

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/admin/people` | Session, **admin** | Everyone with an account, plus invites nobody has opened. |
| `GET` | `/admin/people/:id` | Session, **admin** | One person plus their passkey summaries. `404` for an unknown id **and** for an invite id. |
| `GET` | `/admin/audit` | Session, **admin** | The audit trail. `?person=`, `?action=`, `?before=`, `?limit=`. |
| `POST` | `/admin/people/:id/offboard` | Session, **admin** | Offboard in one action. `409` if already offboarded; `400` on yourself, and `400` on the relay operator. |
| `POST` | `/admin/people/:id/reinstate` | Session, **admin** | Undo an offboarding. `409` unless they are `offboarded`. |
| `POST` | `/admin/people/:id/admit` | Session, **admin** | Admit a pubkey the relay does not have. `400` unless they are `active` and hold a key. |

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

**`admission` was `unknown` for everybody until PEEK-94**, because Buzz exposed
no way to read membership and answering would have meant connecting to another
service's Postgres. Buzz now serves `GET /api/members`, so the other two values
are reachable — the roster is read once per page and indexed locally rather than
asked per pubkey.

**`unknown` did not go away, and must not.** It still means "nobody measured
this", never "probably fine" — the one reading that would make a half-offboarded
person look admitted. `GET /admin/people` therefore also returns
`admissionUnknownReason`, which names *why* nobody could answer:

| Reason | What it means | What fixes it |
| --- | --- | --- |
| `operator-not-configured` | No `RELAY_OPERATOR_USER_ID` | Point it at a role identity, admitted at the relay as an admin |
| `relay-not-configured` | No `RELAY_BRIDGE_URL` | Set it to the workspace relay |
| `operator-inactive` | The operator identity is not `active` here | Reinstate it — which also puts its own admission back |
| `forbidden` | The relay does not accept it as owner/admin | `buzz-admin add-member --role admin` for its pubkey |
| `unreachable` | The relay did not answer | Usually clears itself; until it does, every `admission` is stale |

The two `*-not-configured` values are deliberately separate. Collapsed into one
they had the console recommend setting a variable that was already set — the same
one-label-many-causes failure this field exists to end, one level down.

That field exists because all four rendered as one grey chip, and a workspace
whose operator had been offboarded looked identical to one that never had an
operator at all (PEEK-102). It is workspace-wide, so it is returned once beside
the list rather than on each row — per-row would imply it was measured per
person. The same field comes back from `GET /admin/people/:id`.

The port is `src/domain/admission.ts`, and it is still a port: `RelayAdmission`
asks the relay, `UnobservableAdmission` is what a deployment with no operator
gets, and which one is live is a config question rather than a seam through the
callers.

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
{ "profile": { … },
  "avatar": { "url": "https://id.estiva.app/avatar/<sha256>.jpg",
              "blobUrl": "https://estiva.estiva.app/media/<sha256>.jpg",
              "sha256": "…", "size": 8134 },
  "published": true, "eventId": "…" }
```

The URL is content-addressed, which is the point — Stage 0 published a Convex
storage URL, tying an ecosystem-wide avatar to one deployment's lifetime. `url`
is where a browser can load it and `blobUrl` is where the bytes are; see
`GET /avatar/…` below for why those are two different things.

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

### `GET /avatar/:sha256.:ext`

The URL published as `picture`, and the only one a browser can load.

**Unauthenticated.** The caller is an `<img>` on `peek.estiva.app` or
`ship.estiva.app`: it sends no `Authorization`, and under `SameSite` it sends no
session cookie cross-site either. What replaces per-viewer authorisation is a
narrowing — **a hash is served only while some identity's `picture` still refers
to it**, so this is not a door onto the media store. Buzz's own
feedback-attachment route is built the same way: unreferenced hashes collapse to
`404`.

Any identity, not only an active one. A leaver's messages stay attributed to
them in both apps, so filtering to `active` would blank the face on every
message they ever sent while their name stayed — a different regression, in
service of hiding the least sensitive half. Offboarding revokes what it is
supposed to: the `nip05` attestation, and relay admission. `avatars:republish`
*does* filter to active, for the unrelated reason that re-signing a leaver's
`kind:0` would second-guess a decision already made and audited.

Responses are `public, max-age=31536000, immutable` and `nosniff`. Cacheable at
any length because the URL names the bytes — and necessarily so, since the
alternative is a signed relay round trip for every avatar in every render.

| Condition | HTTP |
| --- | --- |
| Not a blob path, no identity references that hash, or the store does not hold it | 404 |
| `RELAY_OPERATOR_USER_ID` is unset | 500, `detail.reason = no_operator` |
| The operator key is not admitted to the relay | 500, `detail.reason = not_admitted` |
| Media store refused or unreachable | 500 |

A hash nobody references and a hash the store does not hold give **the same**
`404`, so this cannot be used to test whether particular bytes exist.

#### Why the bytes come through here at all (SHA-22)

Buzz used to serve `/media/*` unauthenticated behind
`BUZZ_REQUIRE_MEDIA_GET_AUTH`. Upstream removed that path in `fix(media):
require authenticated reads` and listed both spellings of the variable as
**inert** — so there is no longer a setting an operator can change. Production
reports relay `0.2.1`, which exists only from that merge onward, and answers a
well-formed `/media/<sha256>.jpg` with `401`.

A browser cannot satisfy that. `<img src>` sends no headers, and Buzz's
`extract_blossom_auth` reads the `Authorization` header only — there is no
query-parameter or cookie form of the credential. So *no* app could display an
avatar, however the workspace was configured: every uploaded picture fell back
to initials in Peek and Ship, and this service's own profile page showed a
broken image for a photo it had just stored. Message attachments were unaffected
because Peek kept those in Convex then. They have been in this store since
REM-2 and REM-1 (2026-09-23), and Peek has had no Convex since REM-8.

Handing the browser a credential is what this service exists to avoid, so the
read is signed here instead — `t=get`, scoped to the one hash *and* this host,
by the **relay operator** key rather than the viewer's. `scripts/probe-blossom-read.ts`
verifies that token against the live relay the same way the upload probe does,
including the control that an unauthenticated `GET` is `401`.

#### What `picture` holds, and what is published

`users.picture` keeps the relay's content-addressed URL — that is the record,
and the bytes really are there. `avatarDisplayUrl` maps it to this route on the
way out, so both the published `kind:0` and `GET /me/profile` carry the loadable
URL. The hash survives into it, so an app that has only the published URL can
still derive the relay blob.

**A deploy needs one manual step.** A `kind:0` already on the relay is a copy,
and it still names the `/media/` URL that answers `401` — which is the string
Ship and Peek read. `pnpm avatars:republish` (dry run) / `APPLY=1` re-emits
them; kind:0 is replaceable, so it is a rewrite and safe to run twice.

## Ending a session from an app

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/logout` | — | RP-initiated logout. Revokes the session and redirects back. |

```
/logout?client_id=…&post_logout_redirect_uri=…&state=…
```

`POST /auth/logout` cannot be reached from another origin — the cookie is
`SameSite=Lax` and no CORS is served, so a cross-origin `POST` carries no
session and logs nobody out. This is the same constraint that made `/authorize`
a redirect, with the same answer: a top-level navigation (PEEK-122).

`post_logout_redirect_uri` is validated against **the same registered list as
`/authorize`**, exact-match, before anything is revoked. This endpoint answers
without a session, so an unvalidated URI would be an open redirector that needs
no credentials at all to reach.

**Idempotent.** Logging out a browser that has no session is a `302`, not a
`401` — the caller's intent is "make there be no session", and there being none
already satisfies it.

**It does not revoke tokens already issued.** Access tokens are stateless JWTs
living up to `JWT_TTL_SECONDS`, so an app tab that is already open keeps working
until its expires. What this guarantees is narrower and exact: **no new entry
succeeds.** Every app asks for a passkey the next time it boots. Closing the
remaining window needs PEEK-108 or a per-call revocation check.

A `GET` end-session endpoint is CSRF-able — a third party can force a logout.
That is the accepted shape of OIDC RP-initiated logout: nothing is disclosed,
the impact is annoyance, and a form POST from the app's origin cannot carry the
cookie here anyway.

## Tokens and discovery

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| `GET` | `/.well-known/openid-configuration` | — | Discovery, including `end_session_endpoint`. |
| `GET` | `/.well-known/jwks.json` | — | Active key plus any `previous` one. |
| `GET` | `/authorize` | Session | Browser redirect. Issues an authorization code. |
| `POST` | `/token` | Session, code **or** client secret | Three grants — see below. |

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
  "relayAdmission": { "revoked": true } }
```

**All four steps happen now (PEEK-94).** The fourth used to be undeliverable and
came back as `revoked: false` plus the command a human still had to run. Buzz
accepts membership changes as signed `kind:9031` events through the same bridge
this service already publishes `kind:0` to, so it is driven rather than printed.

`revoked: false` is still reachable — no operator identity, an unreachable relay,
an operator that is not an admin there — and then `reason` and `command` come
back so the step stays completable by hand:

```json
{ "relayAdmission": { "revoked": false, "reason": "the relay operator identity is not active",
                      "command": "docker exec buzz-prod-relay-1 buzz-admin remove-member --pubkey …" } }
```

`attestationPublished: false` means the withdrawal did not reach the relay, so
**the handle still resolves** for anyone reading the old event. The local
revocations happen first precisely so a relay outage cannot leave a login
working.

The key is deliberately **left active** — revoking it would make everything the
person ever signed unattributable, and `/sign` refuses on `users.status` anyway
(PEEK-88).

Two identities are refused, both with `400` and a `detail.reason`:

* **Yourself** (`self_offboard`) — there is no recovery flow (PEEK-67), so it is
  a mistake nobody undoes without shell access.
* **The relay operator** (`operator_identity`) — offboarding it revokes *its own*
  admission, which disables reading and changing admission for the entire
  workspace. This happened on production during PEEK-94 QA, and nothing said so:
  the console afterwards was indistinguishable from a healthy one. Point
  `RELAY_OPERATOR_USER_ID` at another identity first.

Full runbook, including the relay half: [OFFBOARDING.md](OFFBOARDING.md).

### `POST /admin/people/:id/reinstate`

The reverse of offboarding, and it exists because the reverse used to be
`update users set status='active'` against production (PEEK-102).

```json
{ "userId": "…", "pubkey": "…", "needsRecovery": true,
  "relayAdmission": { "admitted": true } }
```

It restores **two** things: account status here, and admission at the relay. The
second is not optional — a status flip alone leaves the pubkey absent from
`relay_members`, so every roster read still `403`s and the reinstatement looks
like it worked. `admitted: false` carries a `reason` and a `command`, exactly as
offboarding does.

It deliberately restores **neither passkeys nor the handle**:

* **Passkeys** stay revoked because the devices holding them left with the
  person. `needsRecovery: true` says a recovery link is the next step — and it is
  `false` only for a role identity, which never had a passkey and signs with a
  client credential offboarding never touched.
* **The handle** may have been taken since it was withdrawn. The person sets it
  again from their account page, which republishes properly.

This is a separate action rather than a relaxation of `createRecovery`'s guard.
That guard refuses a non-active identity so a recovery link can never be a way
back in *around* offboarding, and it stays.

### `POST /admin/people/:id/admit`

The repair path for onboarding (PEEK-65). Enrolment admits the pubkey itself, so
this covers the case where the relay was unreachable at that moment — leaving
somebody `active` here, able to sign in, and able to read nothing in either app.

```json
{ "admitted": true, "alreadyAdmitted": false }
```

Idempotent: the relay treats an add of an existing member as already-in-state and
so does this. Refused with `400` for an identity that is not `active`
(`not_active`) — admitting somebody this service has disabled would re-open the
half offboarding closed — or that holds no key (`no_key`).


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

**`refresh_token`** is how a browser app survives its access token expiring
without a top-level redirect (PEEK-108). Before it existed there was nothing to
exchange, so an expiry cost the page and everything on it — and the mitigation
was an hour-long access token, which bought comfort by widening the window a
leaked one stays useful. With this the access token is back to **ten minutes**.

The body selects the grant; there is one endpoint, which is what discovery
advertises — now as `["authorization_code", "client_credentials",
"refresh_token"]`.

### `GET /authorize`

```
/authorize?client_id=…&redirect_uri=…&response_type=code
          &code_challenge=…&code_challenge_method=S256&state=…&prompt=none
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

**`prompt=none` changes only that last sentence** (PEEK-117). With a live
session it behaves identically — a code goes back to the app. Without one it
returns `?error=login_required&state=…` to the *app* rather than parking the
person on this origin's sign-in page.

That is what an app's auth shell boots on. There is no other way for an app to
ask whether this browser has a session: the cookie is `SameSite=Lax` and no CORS
is served, so a `fetch` and a hidden iframe are both blocked — deliberately, on
the origin holding every custodied key. A top-level navigation is the only thing
that carries the cookie, so the probe *is* the redirect, and behind an app's
loading shell it is invisible.

`login_required` is a successful probe with a negative result, not a bad
request. `prompt` accepts **`none` and nothing else**: a client asking for
`login` or `consent` gets a `400` rather than silently receiving the default.

The unregistered-`redirect_uri` check still runs first, and must: an answer that
needed no session would otherwise make this the open redirector the rest of the
route is arranged to prevent. See [AUTH-SHELL.md](AUTH-SHELL.md) for the
contract apps implement against.

There is no consent screen: every app is first-party. That changes the day a
third-party app is registered.

### `POST /token`

Two request formats. **The standard one is the contract** (record
[sign-in-is-plain-oauth](https://github.com/estiva-app/estiva-docs/blob/main/decisions/sign-in-is-plain-oauth.md),
SPEC §4.4): what any OAuth 2.0 library sends. Estiva's own JSON format stays
until Peek, Ship and Leaf have moved off it, and is then removed.

#### The standard format

`Content-Type: application/x-www-form-urlencoded`, with RFC 6749's names:

```
grant_type=authorization_code&code=…&redirect_uri=…&code_verifier=…&client_id=…
grant_type=refresh_token&refresh_token=…&client_id=…
grant_type=client_credentials&client_id=…&client_secret=…
```

A public client (every app) sends only its `client_id`; a bot's
`client_credentials` request sends its id and secret in HTTP Basic
(`client_secret_basic`) or in the body (`client_secret_post`), never both.
Discovery advertises both as `token_endpoint_auth_methods_supported`. A
parameter with no value counts as absent, one sent twice is refused, and ones
this service does not use (`scope`) are ignored. A form request never falls
back to the session-cookie grant below.

A refusal is RFC 6749 §5.2's shape, `{"error": "…", "error_description": "…"}`
(the description only where it says more than the code):

| `error` | Status | When |
| --- | --- | --- |
| `invalid_request` | 400 | `grant_type` or a parameter the grant needs is missing or malformed, or a parameter is sent twice |
| `unsupported_grant_type` | 400 | a grant other than the three above |
| `invalid_grant` | 400 | a code or refresh token refused for any reason, or the person behind it offboarded or keyless |
| `invalid_client` | 401 | an unknown or disabled app, or a bot's wrong secret |

Every answer from `/token` carries `Cache-Control: no-store` (RFC 6749 §5.1).

#### Estiva's JSON format

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

Its refusals keep this service's own error shape (`{"error": {"code": …}}`),
with the same reasons as the table above.

#### Both formats

Every grant returns the same body. **Every `client_credentials` refusal is
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
{ "access_token": "…", "token_type": "Bearer", "expires_in": 600, "pubkey": "…",
  "issuer": "…", "refresh_token": "…" }
```

`refresh_token` comes back from the **code** and **refresh** grants only. The
session grant is same-origin and `client_credentials` has a secret it can
present again, so neither needs one, and handing a long-lived credential to a
caller with no use for it is pure downside.

### `refresh_token`

```
grant_type=refresh_token&refresh_token=…&client_id=estiva-peek
```

or `{ "grantType": "refresh_token", "refreshToken": "…", "clientId": "estiva-peek" }`
in the JSON format.

A refresh token is the most dangerous thing this service gives a public client:
long-lived, and stored where nothing can keep a secret. Three properties are
what make that acceptable, and all three are load-bearing.

**It rotates.** Every redemption returns a new token and spends the old one, so
a stolen copy stops working the moment the real app refreshes.

**A retry within 30 seconds gets the same answer.** A renewal whose answer was
lost — the laptop slept, the Wi-Fi dropped — leaves
the app holding only the spent token. Presented again by the same app within 30
seconds of its spend, while the new token it bought is still unused, it returns
that same new token (and a fresh access token), so the app stays signed in and
the chain still has one live token. The window is Estiva's own policy (Miky,
2026-10-16), on top of RFC 9700 §4.14.2's rotation and reuse detection. Only
hashes are stored, so the spent row keeps its successor sealed under a key
derived from the spent token itself: the database alone cannot open it. It is
cleared once the 30 seconds are past (`migrations/013_refresh_retry.sql`). The
audit records the retry as `retried: true`.

**Any other replay burns the chain.** Presenting a spent token after those 30
seconds, after its successor was used, or from another app, is not a retry — it
means two parties hold the same credential. There is no way to tell the thief
from the victim, so *every* token in the lineage is revoked, including the
newest, and both are signed out. Without this, rotation is bookkeeping. It is
audited as `outcome: error` rather than `refused`, so it is greppable as the
security event it is.

**It is only as alive as its session.** Redemption re-checks the session, the
app and the person's status. So `/logout` and offboarding end refresh
immediately, rather than leaving a credential that quietly renews a session
somebody thought they had ended.

Every refusal of the token is `invalid_grant`, with the reason in
`audit_events` — same posture as the code grant, and for the same reason. A
disabled app is `invalid_client`.

Claims: `iss` = issuer origin, `sub` = **the user's pubkey**, `aud` = the app's
`client_id`. RS256, not ES256. The reason was Peek's Convex backend, which
rejected ES256 tokens with `Could not verify OIDC token claim` even when they
verified against our own JWKS with a compliant library (`src/domain/jwt.ts`).
**Peek has no Convex since REM-8 (2026-09-25)**, and nothing outside this
service verifies these tokens any more: Peek and Ship present them only back
here, to `/token` and `/sign`. So RS256 is historical rather than required.
Changing `ALG` is a one-line change: `ensureActiveSigningKey` retires a key of
the old algorithm as `previous` and mints a new one.

A third-party relying party would configure itself with the issuer URL and
resolve JWKS through discovery, the same flow as a Clerk or Auth0 integration.
`sub` is then the pubkey.

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
| `relay_auth_missing_relay` | A `22242` event with no `relay` tag, or one that is not a URL. |
| `relay_auth_relay_not_allowed` | The relay is not allowed by both the deployment allowlist and the app's. |

`403` for an unknown app credential or an identity with no active key; `401` for
a missing or invalid token.

Grants and refusals are both written to `audit_events`. Event content is not.

### Policy

Per-app rows in `app_credentials`:

| App | `client_id` | Kinds |
| --- | --- | --- |
| Estiva Peek | `estiva-peek` | 9, 7, 5, 9007, 27235, 1851, 9101, 9002, 9008, 1111, 30078, 41010, 41011, 41012, 22242, 30851, 40003, 1852, 24242, 30840 |
| Estiva Ship | `estiva-ship` | 30850, 30851, 1851, 9, 5, 9007, 9002, 31989, 27235, 1111, 30078, 7, 40003, 1852, 24242, 22242 |

`src/db/seed.ts` is the source; this table is its copy and has lagged it before.

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

### Two kinds are scoped by destination, not only by number

`27235` and `22242` are the only entries in an app's list that are not
self-contained. Every other kind is a thing the app publishes; these two are
**credentials aimed at somewhere**, so the number alone does not say what the
grant is worth.

| Kind | Tag read | Bound by | Match |
| --- | --- | --- | --- |
| `27235` NIP-98 | `u` | `SIGN_NIP98_ALLOWED_URL_PREFIXES` ∩ `app_credentials.nip98_url_prefixes` | prefix |
| `22242` NIP-42 | `relay` | `SIGN_RELAY_AUTH_ALLOWED_URLS` ∩ `app_credentials.relay_auth_urls` | exact, after URL normalization |

Both intersect a deployment bound with a per-app column, so an app can narrow
itself and can never widen past the deployment. Both default to empty, which
means refuse.

**Why 22242 matches exactly where 27235 matches by prefix.** A NIP-98 `u` tag is
a full request URL with a path, so a prefix is the only workable shape. A NIP-42
`relay` tag is a whole relay URL with no path — a prefix buys nothing there and
costs something: `wss://estiva.estiva.app` as a prefix would also admit
`wss://estiva.estiva.app.attacker.example/`. That is the same hazard the
redirect URIs are matched exactly for.

**Why `relay_auth_urls` is its own column** rather than reusing
`nip98_url_prefixes`, which holds the same origin today: they are two
capabilities. NIP-98 reaches the relay's HTTP bridge as a client; NIP-42
authenticates *the user* to a relay over a socket. One column would mean
widening an app's bridge access silently widened what it can authenticate as,
and there would be no way to grant one without the other. It is deliberately not
derived from `RELAY_BRIDGE_URL` either — that is an https origin whose emptiness
means "profile publishing is off", and sharing it would give two capabilities one
switch.

## Encryption

### `POST /nip44/encrypt` and `POST /nip44/decrypt`

Bearer JWT. NIP-44 **v2**, and never NIP-04.

```json
{ "plaintext": "h:9f2c read at 1756000000" }   →   { "ciphertext": "Ag…" }
{ "ciphertext": "Ag…" }                        →   { "plaintext": "h:9f2c read at 1756000000" }
```

**Self-encryption only.** Both operate on
`nip44_conversation_key(own_priv, own_pub)` and neither accepts a peer pubkey.
The request schemas are strict, so sending `pubkey` is a `400` rather than a
field that is ignored — an app that believed it was encrypting to a colleague
must not receive a blob only the user can open.

The distinction is the whole security argument. A general `/decrypt` is a
decryption oracle for anything ever encrypted to that user, DMs included. A
self-only `/decrypt` reads only what the user encrypted to themselves — today,
NIP-RS read state. That is still behavioural data about a person, which is why
the rate limit and the audit rows are here from the first commit rather than
added after.

| Response | When |
| --- | --- |
| `400` | Malformed body, an unknown field, plaintext outside 1–65535 **bytes** of UTF-8, or a ciphertext that will not open |
| `401` | Missing or invalid token |
| `403` | Unknown app credential, no active key, or the person is no longer active |
| `422` | `detail.reason: app_disabled` |
| `429` | 120 operations per minute exceeded, per app per person. `Retry-After` in seconds |

**Every decryption failure gives one answer**, `detail.reason: undecryptable`.
Distinguishing a bad MAC from bad padding to the caller is a padding oracle; the
specific cause goes to `audit_events` instead, where it is useful and out of
reach.

Both endpoints write `nip44.{encrypt,decrypt}.{granted,refused}` audit rows.
**Neither plaintext nor ciphertext is recorded, and neither is their length.**

**Cross-origin** on the same terms as `/sign`.

The rate limit is a **per-process** counter (`src/http/rate-limit.ts`). Estiva ID
runs as one container, so that is a per-deployment limit today; it would not be
under two replicas, and anything that scales this service out has to move the
counter into Postgres or Redis first.

## A bot signed in as its owner (PER-22)

The device flow (RFC 8628's shape, `npm login`'s UX). A **personal bot**, meaning a
role identity with an owner, asks for a session as that owner, and the owner
approves it with a passkey. The bot receives a **session**, not an access token,
because its consumer is a headless browser driving the real apps through
`/authorize`.

| Call | Who | Body → answer |
| --- | --- | --- |
| `POST /device/authorize` | bot | `{ clientId, clientSecret, label? }` → `{ device_code, user_code, verification_uri, verification_uri_complete, expires_in: 600, interval: 5 }` |
| `GET /device/requests/:code` | person | what is asking: `{ botName, clientId, label, ownerDisplayName, expiresAt, sessionHours }` |
| `POST /device/requests/:code/options` | person | WebAuthn options, with the challenge bound to this request |
| `POST /device/requests/:code/approve` | person | a passkey assertion → `{ approved: true }` |
| `POST /device/requests/:code/deny` | anyone with the code | `{ denied: true }` |
| `POST /device/token` | bot | `{ deviceCode, clientId, clientSecret }` → `{ session_token, cookie_name, expires_at, pubkey, delegate_tag }` |
| `GET /me/delegations`, `POST /me/delegations/:id/revoke` | person | list and revoke, from the account page |

The person-facing page is `/device?code=XXXX-XXXX`.

- **Only the bot's owner can approve**, and the check runs after the assertion
  verifies. A workspace role has no owner, so it cannot ask (`401 invalid_client`).
- **Approval is its own ceremony** (`delegation`). A cookie the person already
  holds approves nothing.
- `/device/token` answers RFC 8628's errors as `400 { error }`:
  `authorization_pending`, `slow_down`, `access_denied`, `expired_token` and
  `invalid_grant`. The last covers a collected, unknown or other-bot code. The
  secret is required again, so a leaked device code is worthless.
- **The session reaches app sign-in only.** `requireSession` refuses it with
  `403 detail.reason: delegated_session`, audited as `session.delegate_refused`.
  Only `/me`, `/auth/logout`, `/authorize` and `/token` accept it. It lasts
  `DELEGATED_SESSION_TTL_SECONDS` (24h).
- **Every token minted from it** carries `act: { sub: <bot client id> }` and
  `sid`, and lives `DELEGATED_JWT_TTL_SECONDS` (300s).
- **`/sign`, `/nip44/*` and `/directory/*` re-check the delegation on every
  call.** A revoke, a retired bot or a disabled credential answers the very next
  request with `401 That delegation has ended` (`sign.refused`,
  `delegation_ended`), not when the token expires.
- `/sign` replaces any `client` tag with `["client", "<bot-client-id>-as-<owner>"]`.
  `sign.granted`, `token.*` and `authorize.issue` rows carry `detail.delegate`.

## Test accounts (PER-22)

`POST /auth/test-login { email, secret }` → the session cookie, plus
`{ pubkey, session_token, cookie_name, expires_at }` for a harness with no
cookie jar. The result is an **ordinary member session**, not a delegated one.

- **A sign-in can start older.** `tapped_ago_seconds` and
  `last_used_ago_seconds` (both optional, 0 to 60 days, a last use never before
  the tap) start it as if the tap and its last use were that long ago, so a
  check reaches the 7-day idle end and the 14-day end without waiting. The
  cookie's Max-Age and `expires_at` are what is left of the 14 days.

- **Only a test account can hold a secret, and the schema enforces it.**
  `test_credentials` references `users (id, test_account)` with a composite
  foreign key that resolves only to `true`. A test account is always a human
  `member`: never an admin, never a bot (`users_test_account_is_a_member`).
- **Outside this service they are ordinary people.** Their `kind:0` carries no
  marker, and their messages light dots like anyone's.
- Every refusal is `401 invalid_credentials`. The reason (`unknown`,
  `bad_secret` or `not_active`) is audited as `session.create` with
  `method: test_credential`. The limit is 10 attempts per minute per account.
- Created and rotated from the box only:
  `docker compose run --rm -T -e EMAIL=… -e DISPLAY_NAME=… -e HANDLE=… estiva-id node dist/admin/create-test-account.js`
  (`-e ROTATE=1` replaces the secret). The command admits the pubkey and
  publishes the profile, as enrolment does.
