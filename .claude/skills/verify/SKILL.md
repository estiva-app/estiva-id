---
name: verify
description: Use to prove an Estiva ID change works for the people who sign in through it — the smoke test's sign-in flow on production after a deploy, and the local server and tests before one.
---

# Verifying Estiva ID changes

"It works" is not a result. Say what you checked, as whom, and what the apps showed.

## The smoke test's Estiva ID part

The smoke test ([estiva-app/smoke](https://github.com/estiva-app/smoke), checked out beside this repository as
`../smoke`) walks the core flows on production as two test accounts of its own. Estiva ID's own flow is 6, "Sign in
once, and every app opens signed in" (`../smoke/CORE-FLOWS.md`, "Estiva ID"), and every other flow starts by signing
in through it. `/land` runs every flow after each deploy, once `id.estiva.app/version.json` names the merge commit.

```bash
cd ../smoke && npm ci && node run.mjs --flow 6                 # sign-in only, a minute or two
cd ../smoke && node run.mjs --expect id=<merge commit>         # what /land runs: wait for the deploy, then every flow
```

It exits 0 when every step passed or is known, 1 on a failed step (its screenshot is in `out/<time>/`), 2 when it
could not run. Estiva ID is a server, so unlike Peek, Ship and Leaf it cannot be served to the test from a local
build: the smoke test reaches it only on production. Estiva ID allows about one test sign-in every 30 s, so leave a
minute between runs.

## Before a deploy

`npm test` and `npm run typecheck`. A local server (`pnpm db:up && pnpm migrate && pnpm seed && pnpm dev`, port 8787)
proves the passkey ceremony and the redirect with a virtual authenticator; Peek's
`.claude/skills/verify/scripts/signedIn.mjs` drives one and says how to make the invite it needs. A change to the
seed is checked on production by reading the row through the API after the re-seed, not by the seed's exit code.
