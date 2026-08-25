/**
 * Test environment defaults.
 *
 * CI sets these explicitly; this fills them in for a bare `pnpm test` against a
 * local `pnpm db:up`. Values are deliberately fake — the point of a checked-in
 * KEK is that it protects nothing real.
 */
const defaults: Record<string, string> = {
  NODE_ENV: 'test',
  LOG_LEVEL: 'silent',
  DATABASE_URL: 'postgres://estiva:estiva@localhost:5433/estiva_id',
  ISSUER_URL: 'http://localhost:8787',
  RP_ID: 'localhost',
  RP_NAME: 'Estiva ID (test)',
  RP_ORIGINS: 'http://localhost:8787',
  KEY_ENCRYPTION_KEK: '1111111111111111111111111111111111111111111111111111111111111111',
  KEY_ENCRYPTION_KID: 'test-1',
  SIGN_NIP98_ALLOWED_URL_PREFIXES: 'http://relay.test/',
  // Deliberately without a trailing slash, while the events under test carry
  // one: the seeded value and the wire value are spelled differently in
  // practice, and normalizing both sides is the thing that has to keep working.
  SIGN_RELAY_AUTH_ALLOWED_URLS: 'ws://relay.test',
}

for (const [key, value] of Object.entries(defaults)) {
  process.env[key] ??= value
}
