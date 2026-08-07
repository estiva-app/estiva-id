/**
 * Test database helpers.
 *
 * Tests run against a real Postgres (`pnpm db:up`), not a mock — the things
 * worth testing here are transactional and constraint-shaped, and a fake would
 * only confirm the fake.
 */
import { migrate } from '../db/migrate.js'
import { query } from '../db/pool.js'
import { seedApps } from '../db/seed.js'

let prepared = false

export async function prepareDatabase(): Promise<void> {
  if (prepared) return
  await migrate()
  prepared = true
}

/** Wipe user-owned data between tests. `app_credentials` is re-seeded. */
export async function truncateAll(): Promise<void> {
  await query(
    `truncate users, webauthn_credentials, webauthn_challenges, user_keys,
              user_handles, sessions, audit_events, app_credentials, jwt_signing_keys
     restart identity cascade`,
  )
  await seedApps()
}
