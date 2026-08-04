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
import { closePool, query } from './pool.js'

interface SeedApp {
  clientId: string
  name: string
  allowedKinds: number[]
  nip98UrlPrefixes: string[]
}

export const SEED_APPS: readonly SeedApp[] = [
  {
    clientId: 'estiva-peek',
    name: 'Estiva Peek',
    // PEEK-71: 9 (chat message), 7 (reaction), 5 (deletion), 9007 (huddle).
    allowedKinds: [9, 7, 5, 9007],
    nip98UrlPrefixes: [],
  },
  {
    clientId: 'linear-lite',
    name: 'Estiva Projects (linear-lite)',
    // PEEK-71: 30850, 30851, 1851, 9, 5, 31989.
    allowedKinds: [30850, 30851, 1851, 9, 5, 31989],
    nip98UrlPrefixes: [],
  },
]

export async function seedApps(): Promise<void> {
  for (const app of SEED_APPS) {
    await query(
      `insert into app_credentials (client_id, name, allowed_kinds, nip98_url_prefixes)
       values ($1, $2, $3, $4)
       on conflict (client_id) do update
         set name = excluded.name,
             allowed_kinds = excluded.allowed_kinds,
             nip98_url_prefixes = excluded.nip98_url_prefixes,
             updated_at = now()`,
      [app.clientId, app.name, app.allowedKinds, app.nip98UrlPrefixes],
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
