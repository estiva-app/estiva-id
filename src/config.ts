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

  /**
   * How long an access token lives.
   *
   * **Ten minutes again (PEEK-108).** It was raised to an hour because nothing
   * could mint a fresher one: there was no refresh grant, and the session that
   * would authorise a silent renewal is a `SameSite=Lax` cookie, withheld from
   * the hidden iframe such a renewal would need. So an expired token cost a
   * browser app a top-level redirect and whatever was on screen, and an hour
   * was the least-bad trade.
   *
   * The refresh grant removes the reason for the trade, so the number goes
   * back. Every extra minute here is another minute a leaked token stays
   * useful — and Peek passes these as Convex action arguments, which Convex
   * surfaces in its dashboard logs (PEEK-106).
   *
   * It also decides how quickly signing out takes effect elsewhere. Access
   * tokens are stateless and cannot be revoked, so an already-open tab in
   * another app keeps working until its token expires: ten minutes rather than
   * an hour (PEEK-122). Refresh *is* revoked, so nothing renews past it.
   */
  JWT_TTL_SECONDS: z.coerce.number().int().positive().default(600),

  /**
   * URL prefixes that a NIP-98 (kind 27235) event may target. Empty means
   * **refuse all 27235 signing** — the relay bridge host follows from PEEK-33,
   * and fail-closed matches Buzz's own posture on `pubkey_allowlist`.
   */
  SIGN_NIP98_ALLOWED_URL_PREFIXES: commaSeparated,

  /**
   * Relays a NIP-42 (kind 22242) challenge response may be signed for. Empty
   * means **refuse all 22242 signing**, the same fail-closed posture as the
   * NIP-98 list above and for a sharper reason: a 22242 authenticates the user
   * themselves to whichever relay issued the challenge, so an unbounded list is
   * an app that can be the user at any relay on the internet.
   *
   * Whole relay URLs, e.g. `wss://estiva.estiva.app`, and **matched exactly**
   * after normalization rather than by prefix — see `domain/policy.ts`. A
   * trailing slash makes no difference; a different host does.
   *
   * Deliberately not derived from `RELAY_BRIDGE_URL` below, which is the same
   * host today. That one is an https origin for the HTTP bridge and empty means
   * "profile publishing is off"; reusing it would make turning publishing off
   * also turn relay auth off, and would give the two capabilities one switch.
   */
  SIGN_RELAY_AUTH_ALLOWED_URLS: commaSeparated,

  /**
   * Where profiles are published (PEEK-31). Empty means **publishing is off**,
   * which is the flag: a deployment with no relay still serves auth and tokens,
   * it just cannot make a profile visible to anyone.
   *
   * This is the origin of Buzz's HTTP bridge, e.g. `https://estiva.estiva.app`.
   */
  RELAY_BRIDGE_URL: z
    .string()
    .default('')
    .transform((raw) => raw.trim().replace(/\/+$/, '')),

  /**
   * The community host handles belong to — `estiva.estiva.app`.
   *
   * Not derived from RELAY_BRIDGE_URL even though they are the same string
   * today. The relay is *where we publish*; the community host is *what a
   * handle claims*, and Buzz compares the latter against `communities.host`
   * with an exact string match. Conflating them means a bridge that moves
   * behind a different origin silently rewrites everyone's handle.
   */
  COMMUNITY_HOST: z
    .string()
    .default('')
    .transform((raw) => raw.trim().toLowerCase().replace(/\.$/, '')),

  /**
   * The identity whose custodied key signs relay-operator actions (PEEK-94).
   *
   * Reading the roster and adding or removing members are all restricted by
   * Buzz to relay `owner`/`admin`, so they cannot be signed as the person being
   * acted on — who is very often precisely the one who is *not* a member. They
   * are signed as an operator instead.
   *
   * A **role identity** (PEEK-34) is the right shape for it: org-custodied
   * outright, no passkey, nobody to sign in as it. Bootstrapping is one manual
   * step, because the first admission cannot be granted by the thing asking for
   * it — create the role identity, then admit its pubkey at the relay:
   *
   *   docker exec buzz-prod-relay-1 buzz-admin add-member --pubkey <hex> --role admin
   *
   * Empty means relay membership stays unobservable and offboarding keeps
   * printing a command for a human. That is the pre-PEEK-94 behaviour, and it
   * is the honest fallback rather than a broken one.
   */
  RELAY_OPERATOR_USER_ID: z.string().default(''),

  /**
   * Where each app may be sent back to after `/authorize` (PEEK-90),
   * comma-separated and matched **exactly**.
   *
   * Empty means that app cannot use the redirect flow — the same fail-closed
   * posture as the NIP-98 allowlist, and for a sharper reason: the thing being
   * redirected is an authorization code, so a loose entry here is an account
   * takeover rather than a nuisance.
   *
   * Exact, never prefix. As a prefix, `https://app.test/cb` would also permit
   * `https://app.test/cb.attacker.example`.
   */
  PEEK_REDIRECT_URIS: commaSeparated,
  SHIP_REDIRECT_URIS: commaSeparated,
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
