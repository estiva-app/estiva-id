/**
 * Typed configuration, validated once at boot.
 *
 * Two rules here:
 *
 *   1. **Fail loudly.** A missing or malformed value throws before the server
 *      listens. Silently defaulting a key-encryption key or an RP ID would be
 *      worse than not starting.
 *   2. **Unresolved architecture is configuration, not code.** The domain
 *      layout (PEEK-33) and the relay bridge URL are deliberately undecided, so
 *      they arrive as env values with fail-closed defaults rather than
 *      constants compiled into the service.
 */
import { z } from 'zod'
import { loadEnvFile } from './env-file.js'

/** 32 bytes, hex-encoded — the AES-256 key-encryption key. */
const hex32Bytes = z.string().regex(/^[0-9a-f]{64}$/i, 'must be 64 hex characters (32 bytes)')

const commaSeparated = z
  .string()
  .default('')
  .transform((raw) =>
    raw
      .split(',')
      .map((part) => part.trim())
      .filter((part) => part.length > 0),
  )

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().positive().default(8787),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),

  DATABASE_URL: z.string().min(1),

  /**
   * The issuer identity, as it appears in JWTs and OIDC discovery. Must be the
   * public HTTPS origin in production — relying parties resolve JWKS from it.
   */
  ISSUER_URL: z.string().url(),

  /**
   * WebAuthn relying party. RP_ID is origin-bound and **changing it invalidates
   * every enrolled credential**, so it is entangled with the undecided domain
   * layout (PEEK-33). Kept as config precisely so that decision stays open.
   */
  RP_ID: z.string().min(1).default('localhost'),
  RP_NAME: z.string().min(1).default('Estiva ID'),
  /** Allowed WebAuthn origins. More than one during a domain migration. */
  RP_ORIGINS: commaSeparated.pipe(z.array(z.string().url()).min(1)),

  /**
   * Key-encryption key for the custody envelope, and its identifier. The KEK
   * lives in the environment and never in Postgres — that separation is what
   * makes "a database dump alone does not yield signing keys" true (PEEK-27).
   */
  KEY_ENCRYPTION_KEK: hex32Bytes,
  KEY_ENCRYPTION_KID: z.string().min(1).default('deploy-1'),

  SESSION_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(60 * 60 * 12),
  JWT_TTL_SECONDS: z.coerce
    .number()
    .int()
    .positive()
    .default(60 * 10),

  /**
   * URL prefixes that a NIP-98 (kind 27235) event may target. Empty means
   * **refuse all 27235 signing** — the relay bridge host follows from PEEK-33,
   * and fail-closed matches Buzz's own posture on `pubkey_allowlist`.
   */
  SIGN_NIP98_ALLOWED_URL_PREFIXES: commaSeparated,
})

export type Config = z.infer<typeof schema>

let cached: Config | undefined

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env)
  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => `  ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n')
    throw new Error(`Invalid configuration:\n${detail}`)
  }
  return parsed.data
}

/** Process-wide config. Throws on first access if the environment is invalid. */
export function config(): Config {
  if (cached === undefined) {
    loadEnvFile()
    cached = loadConfig()
  }
  return cached
}

/** Test seam — drop the memoised config so a new environment takes effect. */
export function resetConfigForTests(): void {
  cached = undefined
}
