# The auth shell contract

How a protected app enters. Peek and Ship implement this; a future app should be
able to implement it without re-deciding any of it (PEEK-115).

The goal is that authentication stops being a thing an app *has*. There is one
authentication authority, and an app's only job is to bootstrap against it. So
there is no app-owned sign-in screen anywhere in this contract — not as a
fallback, not as a dead end. What an app owns is a **shell**: the surface it
shows while it works out whether it can enter, which doubles as the place a
passkey is invoked when it cannot.

## The one mechanism, and why there is only one

**Silent entry is a top-level redirect.** Not a `fetch`, not a hidden iframe.

Estiva ID's session cookie is `SameSite=Lax` and the origin serves no CORS.
Lax cookies ride top-level navigations and nothing else, so a cross-origin fetch
is blocked twice over and an iframe gets no cookie at all. Both properties are
deliberate on the origin that holds every custodied signing key, and neither is
worth relaxing to save a navigation — `SameSite=None` would make the identity
session a third-party cookie, which is both a real security downgrade and a bet
against Safari's ITP and Chrome's third-party cookie policy.

So the probe *is* the redirect. `GET /authorize?prompt=none` (PEEK-117) answers
in one of three ways, and behind a shell that renders as app bootstrap the whole
round trip is invisible:

| Outcome | Comes back as | Means |
| --- | --- | --- |
| Live session | `?code=…&state=…` | Enter immediately |
| No session | `?error=login_required&state=…` | Passkey required |
| Identity not active | `?error=access_denied&state=…` | Suspended or offboarded |

**The one interaction that cannot be removed is the passkey tap.** WebAuthn
requires a user activation, so no design — this one or any other — can invoke a
passkey ceremony automatically on page load. The honest budget is therefore:

* already signed in → **zero interactions**
* not signed in → **one tap**, inside the app's own shell

## States

Five, and no more. Anything an app wants to distinguish beyond this belongs in
`reason`, not in a new state.

```
                   ┌───────────────────────────────┐
  load ──▶ checking ──▶ entering ──▶ ready         │
              │                                    │
              ├──▶ authenticating ──(tap)──▶ ID ───┘
              │
              └──▶ failed(reason) ──(retry)──▶ checking
```

| State | What is true | What the shell shows |
| --- | --- | --- |
| `checking` | Deciding whether entry is possible. A stored token is being validated, or the probe is in flight. | Bootstrap surface. Nothing about auth. |
| `entering` | A token is held; app-side bootstrap is running (Peek: `adoptIdentity`). | Same bootstrap surface — this is not a separate screen. |
| `authenticating` | Entry needs a passkey. Waiting on the one unavoidable tap. | The same surface plus one continue affordance. |
| `ready` | The app owns the screen. | Nothing — the shell is gone. |
| `failed` | Entry did not happen and will not without intervention. | The reason, honestly, and a retry. |

`checking` and `entering` deliberately render the same thing. The transition
between them is not information a person entering their own app needs, and
showing it invites two visibly different loading screens for one boot.

## Reasons

`failed` is never bare. Every reason below is separately reachable, and they are
not interchangeable — the whole point is that a person is never told to
re-authenticate against a wall.

| `reason` | Cause | Retry does |
| --- | --- | --- |
| `no_session` | Probe returned `login_required` | Offers the passkey |
| `session_expired` | Held token expired and the probe found no session | Offers the passkey |
| `identity_inactive` | `access_denied` — suspended or offboarded | Nothing. An admin must act. |
| `token_rejected` | A **live** token the app's backend refused | Nothing. See below. |
| `exchange_failed` | `/token` refused the code — expired (60s), replayed, wrong verifier | Restarts the flow |
| `network` | Estiva ID unreachable | Restarts the flow |
| `timeout` | Probe did not resolve within budget | Restarts the flow |
| `loop_guard` | A silent attempt already ran this page-load chain and came back empty | Offers the passkey, never another silent attempt |

**`token_rejected` is the one that must never read as "signed out."** A live
token the backend refuses is a configuration fault — wrong issuer, wrong
audience, unreachable JWKS — and signing in again cannot fix it. Peek learned
this the expensive way; the distinction predates this contract and survives it.

## The loop guard

This is the load-bearing safety property, and the reason automatic entry is
safe to do at all.

Peek's pre-shell sign-in screen was a button rather than an auto-redirect on
purpose, and its comment says why: *"auto-bouncing would loop indefinitely
whenever the identity session had expired too. A loop is a far worse failure
than one click."* That hazard is real. An app that redirects on every boot with
no session, against a service that redirects straight back, is an infinite
bounce that burns a person's battery and shows them nothing.

The guard:

1. Before navigating for a **silent** attempt, write a marker to
   `sessionStorage` with a timestamp.
2. On boot, if the marker exists, is recent, and no token was obtained, do
   **not** navigate again. Enter `authenticating` and wait for the tap.
3. Clear the marker on successful token receipt.

One silent attempt per page-load chain, then a human-visible state. `sessionStorage`
is the right scope: it is per-tab and dies with it, so a genuinely new session
gets a genuinely fresh attempt.

The elapsed time in the marker is also how `timeout` is detected. A navigation
cannot be timed out from the page that is being unloaded, but a return trip that
took far longer than a redirect should is a slow or partially-failing identity
service, and that is worth saying rather than absorbing.

## Sequencing

```
boot
 ├─ is this load a callback? (?code= or ?error= present)
 │    yes → verify state, exchange code, clear query, → entering
 ├─ stored token still valid?
 │    yes → entering
 ├─ loop guard already tripped?
 │    yes → authenticating
 └─ set marker, navigate to /authorize?prompt=none
```

Two details that are contract, not implementation:

**The query is cleared either way.** A spent authorization code left in the
address bar is in browser history and in every screenshot.

**`redirect_uri` is compared exact-string.** The shell must not append a query
or a hash to it. A trailing slash is a different URI and earns a `400` before
anything else happens.

## What is deliberately not here

* **Account switching.** One active identity is the only case. A shell that
  supported switching would need an account picker, which is the app-specific
  sign-in surface this contract exists to delete.
* **Refresh.** There is no refresh grant (PEEK-108). An expired token costs a
  round trip through this same flow, which is silent when the session is live.
  That is the whole reason `JWT_TTL_SECONDS` is an hour rather than ten minutes.
* **Sign-out UI.** Out of scope for entry. Clearing the app's stored token is
  not the same act as ending the Estiva ID session, and conflating them is its
  own ticket.
