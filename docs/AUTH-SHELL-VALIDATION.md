# Validating the auth shell

How to tell whether entry is actually working, and the demo path for M5
(PEEK-120).

## Reading it in production

Everything needed is already in `audit_events`, visible at `/admin/audit` and
filterable by `?action=`. No new store, because the identity service is the one
place both apps are visible at once — instrumenting each app separately would
produce two numbers nobody can compare, which is the thing this ticket asks not
to happen.

| Action | `detail` | What it counts |
| --- | --- | --- |
| `authorize.probe` (`refused`) | `reason: login_required` | A shell asked and there was no session |
| `authorize.issue` (`success`) | `silent: true` | **Entry that cost the person nothing** |
| `authorize.issue` (`success`) | `silent: false` | Entry after a passkey tap |
| `authorize.issue` (`refused`) | `reason: user_*` | Suspended or offboarded, sent back as `access_denied` |

`actor_client_id` is `estiva-peek` or `estiva-ship` on every row, so each rate
splits per app:

* **shell entry rate** — probes + issues
* **immediate-entry success rate** — `silent: true` issues ÷ probes
* **passkey-invocation rate** — `silent: false` issues ÷ probes
* **failure** — refusals, by reason

The one number that is *not* here is drop-off between the shell and an
authenticated app: a person who gets a code and never comes back has left no
row on this side. That is the gap — see below.

### In the browser

Both apps emit the same line, so a console filtered on `[auth-shell]` reads the
same in either:

```
[auth-shell] estiva-peek checking +2ms
[auth-shell] estiva-peek entering +812ms
```

Failures are `console.error`, not `warn`. A `warn` at boot is indistinguishable
from the noise every app already makes, and the point of this ticket is that a
broken entry is loud.

`token_rejected` is the one worth watching for. It means Convex refused a live
token — issuer, audience or JWKS — and no amount of re-authenticating fixes it.

## The demo path

Run it in this order. Each step is checking a different thing, and step 2 is
the milestone.

**Setup.** A browser with no `id.estiva.app` cookie — a fresh profile, not an
incognito window you have already signed into. Have `/admin/audit` open in a
second window on another profile, filtered to `authorize.probe`.

1. **Cold, no identity session.** Open `https://peek.estiva.app`.
   *Expect:* a brief bootstrap screen, then "Continue with your passkey to
   enter." **No "Sign in with Estiva ID" page anywhere.** One new
   `authorize.probe` / `login_required` row.

2. **The passkey, in place.** Tap Continue.
   *Expect:* the platform passkey prompt, then Peek. One `authorize.issue`
   with `silent: false`.

3. **The point of the milestone.** Open `https://ship.estiva.app` in a new tab.
   *Expect:* **you are simply in Ship.** No prompt, no tap, no sign-in screen —
   a bootstrap screen for a moment at most. One `authorize.issue` with
   `silent: true`. This is the claim: two apps, one identity, and the second
   one asked you for nothing.

4. **Consistency.** Compare the two shells side by side. Same copy, same
   states, same shape — Peek in React, Ship in plain DOM.

5. **The loop guard.** In Ship's tab, DevTools → Application → Cookies →
   `id.estiva.app`, delete the session cookie. Reload.
   *Expect:* one silent probe, then the passkey affordance. **Watch the network
   panel: exactly one round trip to `/authorize`, not a stream of them.** This
   is the failure the guard exists to prevent and it is invisible unless you
   look.

6. **Honest failure.** Offboard a test identity in the admin console, then
   reload its app tab.
   *Expect:* "This identity is not active. An administrator needs to restore
   it," and **no retry button** — a passkey cannot fix it, so the shell does
   not pretend otherwise.

7. **Sign-out.** Ship → profile menu → Sign out.
   *Expect:* the shell, offering a passkey. Tapping it puts you back with no
   prompt, because the Estiva ID session is still live. That is correct: the
   app forgot your token, which is not the same act as ending your session.

## What this does not prove

**Cross-origin behaviour is not covered by any test suite, in any of the three
repos.** Nothing enforces CORS or cookie policy when a Hono app is called
in-process — that is exactly how PEEK-90 shipped green tests and a feature that
could not work, and how PEEK-93's missing `OPTIONS` handler survived a full
passing suite. Steps 1–3 are the only thing that checks this, and they have to
be done in a real browser across real origins.

**Third-party cookie policy is load-bearing and untested here.** The flow is
built on top-level navigations precisely so it does not depend on third-party
cookies, but `SameSite=Lax` on `estiva_id_session` is what the whole silent path
rests on. If that ever becomes `None`, re-run this in Safari before believing
anything.

**Drop-off after the code is issued is not measured.** A person who gets a code
and never reaches the app — a failed exchange, a closed tab — leaves an
`authorize.issue` and nothing after it. Closing that needs the apps to report
completion back, which is a bigger change than this milestone wanted and is the
honest limit of "drop-off points" in PEEK-120.
