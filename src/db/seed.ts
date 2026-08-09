/**
 * Development seed: the two app credentials the suite already needs.
 *
 * The kind lists come from PEEK-71 and are knowable from what each app
 * publishes today. They live in the database rather than in code because the
 * set changes when an app gains a feature, and that should not be a deploy of
 * the identity service.
 *
 * NIP-98 prefixes are left empty on purpose: the relay bridge host follows from
 * the undecided domain layout (PEEK-33), and an empty list refuses all 27235.
 */
import { config } from '../config.js'
import { closePool, query } from './pool.js'

interface SeedApp {
  clientId: string
  name: string
  allowedKinds: number[]
  nip98UrlPrefixes: string[]
  /** Where `/authorize` may send this app back to. Exact match — see config. */
  redirectUris: () => string[]
}

/**
 * Apps default to whatever this deployment allows, rather than a hardcoded
 * hostname — the relay's address differs per workspace and per environment, and
 * `SIGN_NIP98_ALLOWED_URL_PREFIXES` is already the single place that says it.
 *
 * Seeding both apps identically does not make the per-app column pointless: it
 * is the ceiling that can be lowered later, e.g. to bar an app from
 * `/media/upload` while still letting it publish. Widening is impossible — the
 * deployment bound always applies as well.
 */
const relayPrefixes = (): string[] => [...config().SIGN_NIP98_ALLOWED_URL_PREFIXES]

export const SEED_APPS: readonly SeedApp[] = [
  {
    clientId: 'estiva-peek',
    name: 'Estiva Peek',
    // PEEK-71: 9 (chat message), 7 (reaction), 5 (deletion), 9007 (huddle).
    // 27235 is NIP-98 HTTP auth — without it the app cannot authenticate to the
    // relay's bridge at all, so it can hold a signed event and still not publish.
    allowedKinds: [9, 7, 5, 9007, 27235],
    nip98UrlPrefixes: [],
    redirectUris: () => [...config().PEEK_REDIRECT_URIS],
  },
  {
    clientId: 'linear-lite',
    name: 'Estiva Ship (linear-lite)',
    // PEEK-71: 30850, 30851, 1851, 9, 5, 31989 — plus 27235, as above.
    allowedKinds: [30850, 30851, 1851, 9, 5, 31989, 27235],
    nip98UrlPrefixes: [],
    redirectUris: () => [...config().SHIP_REDIRECT_URIS],
  },
]

export async function seedApps(): Promise<void> {
  for (const app of SEED_APPS) {
    await query(
      `insert into app_credentials
         (client_id, name, allowed_kinds, nip98_url_prefixes, redirect_uris)
       values ($1, $2, $3, $4, $5)
       on conflict (client_id) do update
         set name = excluded.name,
             allowed_kinds = excluded.allowed_kinds,
             nip98_url_prefixes = excluded.nip98_url_prefixes,
             redirect_uris = excluded.redirect_uris,
             updated_at = now()`,
      [
        app.clientId,
        app.name,
        app.allowedKinds,
        // Empty in the table means "this deployment allows none", so default to
        // the deployment's own list rather than seeding an app that is allowed
        // a kind it can never actually use.
        app.nip98UrlPrefixes.length > 0 ? app.nip98UrlPrefixes : relayPrefixes(),
        app.redirectUris(),
      ],
    )
  }
}

if (process.argv[1]?.endsWith('seed.ts') || process.argv[1]?.endsWith('seed.js')) {
  try {
    await seedApps()
    process.stdout.write(`seeded ${SEED_APPS.length} app credential(s)\n`)
  } finally {
    await closePool()
  }
}
