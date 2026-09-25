/**
 * Token issuance and the JWKS the rest of the suite validates against (PEEK-29).
 *
 * `sub` is the user's **pubkey**, not an internal id. That is the whole point:
 * Convex resolves `getUserIdentity().subject`, and if that is the pubkey then an
 * app knows who signed an event without asking this service anything.
 *
 * `aud` is the **client id of the app the token was issued to**. Together with
 * `app_credentials` that is what makes PEEK-71's per-app signing policy
 * enforceable: the audience selects the policy row, so a token lifted out of one
 * app cannot be replayed against another app's looser kind list.
 *
 * The signing key is persisted, not generated per boot. JWKS has to be stable
 * across restarts and replicas, or relying parties see tokens signed by a `kid`
 * that discovery does not list. Its private half is sealed in the same envelope
 * as user keys, so a database dump does not permit token forgery either.
 */
import {
  type JWK,
  SignJWT,
  calculateJwkThumbprint,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
} from 'jose'
import { config } from '../config.js'
import { type Envelope, openEnvelope, sealEnvelope } from '../crypto/envelope.js'
import { query, queryOne } from '../db/pool.js'
import { unauthenticated } from '../errors.js'
import { currentKek, currentKid, resolveKek } from './kek.js'

/**
 * RS256, not ES256.
 *
 * Convex rejects ES256 tokens with "Could not verify OIDC token claim", even
 * though the same token verifies cleanly against our published JWKS with a
 * standards-compliant library. Convex's own auth package signs RS256 and
 * nothing in it mentions ES256, so RSA appears to be what its validator
 * accepts. Its docs do not state a supported set, so this is empirical.
 *
 * ES256 is the nicer choice on the merits — smaller keys, smaller signatures —
 * but "the relying party accepts it" beats elegance, and Convex is the relying
 * party this exists to serve.
 */
const ALG = 'RS256'

interface SigningKeyRow {
  kid: string
  public_jwk: JWK
  private_jwk_envelope: Envelope
}

/**
 * Ensure there is an active signing key, creating one on first use.
 *
 * The insert is conditional, so two replicas racing at cold start end up
 * agreeing on one key rather than each serving tokens the other's JWKS omits.
 */
export async function ensureActiveSigningKey(): Promise<string> {
  const existing = await queryOne<{ kid: string; alg: string }>(
    "select kid, alg from jwt_signing_keys where status = 'active'",
  )

  // An active key signed with a different algorithm than we now use cannot be
  // loaded — `importJWK` would be handed an EC key and asked for RSA. Retire it
  // and mint a replacement rather than crashing on every request until someone
  // edits the database by hand. It stays in JWKS as `previous`, so tokens
  // issued moments earlier keep validating until they expire.
  if (existing && existing.alg !== ALG) {
    await query("update jwt_signing_keys set status = 'previous' where kid = $1", [existing.kid])
  } else if (existing) {
    return existing.kid
  }

  const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true })
  const publicJwk = await exportJWK(publicKey)
  const privateJwk = await exportJWK(privateKey)
  const kid = await calculateJwkThumbprint(publicJwk)

  const envelope = sealEnvelope({
    secret: Buffer.from(JSON.stringify(privateJwk), 'utf8'),
    aad: { kid, purpose: 'jwt-signing' },
    kek: currentKek(),
    kid: currentKid(),
  })

  await query(
    `insert into jwt_signing_keys (kid, alg, public_jwk, private_jwk_envelope, status)
     values ($1, $2, $3, $4, 'active')
     on conflict (kid) do nothing`,
    [
      kid,
      ALG,
      JSON.stringify({ ...publicJwk, kid, alg: ALG, use: 'sig' }),
      JSON.stringify(envelope),
    ],
  )

  const active = await queryOne<{ kid: string }>(
    "select kid from jwt_signing_keys where status = 'active'",
  )
  return active?.kid ?? kid
}

/** Whatever `importJWK` hands back, without naming a DOM type on a server. */
type ImportedKey = Awaited<ReturnType<typeof importJWK>>

async function loadActiveSigningKey(): Promise<{ kid: string; key: ImportedKey }> {
  const kid = await ensureActiveSigningKey()
  const row = await queryOne<SigningKeyRow>(
    'select kid, public_jwk, private_jwk_envelope from jwt_signing_keys where kid = $1',
    [kid],
  )
  if (!row) throw new Error('active signing key vanished')

  const decrypted = openEnvelope({
    envelope: row.private_jwk_envelope,
    aad: { kid: row.kid, purpose: 'jwt-signing' },
    resolveKek,
  })
  try {
    const jwk = JSON.parse(decrypted.toString('utf8')) as JWK
    return { kid: row.kid, key: await importJWK(jwk, ALG) }
  } finally {
    decrypted.fill(0)
  }
}

export interface IssuedToken {
  token: string
  expiresIn: number
  pubkey: string
}

/**
 * A bot acting as the token's subject, through a session the subject granted
 * it (PER-22).
 */
export interface TokenDelegate {
  /** The bot's service credential — `act.sub`. */
  clientId: string
  /** The delegated session — `sid`. What `/sign` re-checks on every call. */
  sessionId: string
}

export async function issueToken(input: {
  pubkey: string
  clientId: string
  delegate?: TokenDelegate | undefined
}): Promise<IssuedToken> {
  const cfg = config()
  const { kid, key } = await loadActiveSigningKey()

  /*
    RFC 8693's actor claim: `sub` is still the person — the key that signs, and
    what Convex reads as the user — and `act` says who is actually driving.
    A relying party that ignores `act` sees the person, which is correct for
    what it decides; this service reads it back on every `/sign`.
  */
  const claims = input.delegate
    ? { act: { sub: input.delegate.clientId }, sid: input.delegate.sessionId }
    : {}
  const ttl = input.delegate
    ? Math.min(cfg.DELEGATED_JWT_TTL_SECONDS, cfg.JWT_TTL_SECONDS)
    : cfg.JWT_TTL_SECONDS

  const token = await new SignJWT(claims)
    .setProtectedHeader({ alg: ALG, kid, typ: 'JWT' })
    .setIssuer(cfg.ISSUER_URL)
    .setSubject(input.pubkey)
    .setAudience(input.clientId)
    .setIssuedAt()
    .setExpirationTime(`${ttl}s`)
    .sign(key)

  return { token, expiresIn: ttl, pubkey: input.pubkey }
}

/** Public JWKS — the active key plus any `previous` one, so rotation is not a cliff. */
export async function publicJwks(): Promise<{ keys: JWK[] }> {
  await ensureActiveSigningKey()
  const result = await query<{ public_jwk: JWK }>(
    "select public_jwk from jwt_signing_keys where status in ('active', 'previous') order by created_at desc",
  )
  return { keys: result.rows.map((row) => row.public_jwk) }
}

export interface VerifiedToken {
  /** The user's pubkey — `sub`. */
  pubkey: string
  /** The app the token was issued to — `aud`. Selects the signing policy. */
  clientId: string
  /** Present when a bot holds the token as the subject — `act` and `sid`. */
  delegate?: TokenDelegate | undefined
}

function readDelegate(payload: Record<string, unknown>): TokenDelegate | undefined {
  const act = payload.act
  if (act === undefined) return undefined
  const actor = typeof act === 'object' && act !== null ? (act as { sub?: unknown }).sub : undefined
  // Half a delegation is refused, not read as none: a token naming a bot with
  // no session to check would otherwise sign as the person unconditionally.
  if (typeof actor !== 'string' || typeof payload.sid !== 'string') {
    throw new Error('token carries an incomplete act claim')
  }
  return { clientId: actor, sessionId: payload.sid }
}

/**
 * Verify a token this service issued.
 *
 * Audience is *read*, not asserted, because `/sign` needs to know which app is
 * calling in order to pick its policy. Issuer and signature are asserted.
 */
export async function verifyToken(token: string): Promise<VerifiedToken> {
  const cfg = config()
  const jwks = createLocalJWKSet(await publicJwks())

  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: cfg.ISSUER_URL,
      algorithms: [ALG],
    })

    const audience = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud
    if (!payload.sub || !audience) throw new Error('token is missing sub or aud')

    return { pubkey: payload.sub, clientId: audience, delegate: readDelegate(payload) }
  } catch (error) {
    throw unauthenticated(`Invalid token: ${(error as Error).message}`)
  }
}

/**
 * OIDC discovery document.
 *
 * Still not a general-purpose OpenID Provider — no refresh tokens, no id_token,
 * no userinfo. It advertises what a relying party needs to find and trust the
 * JWKS (which is what `convex/auth.config.ts` resolves from `domain`), plus the
 * authorization code flow added in PEEK-90 so a browser app on another origin
 * can obtain a token at all.
 */
export function discoveryDocument(): Record<string, unknown> {
  const issuer = config().ISSUER_URL
  return {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    // RP-initiated logout (PEEK-122). Advertised because an app cannot end a
    // session any other way — the cookie is SameSite=Lax and no CORS is served,
    // so a cross-origin POST to /auth/logout carries nothing and logs nobody
    // out. It takes `post_logout_redirect_uri`, validated against the same
    // registered list as /authorize.
    end_session_endpoint: `${issuer}/logout`,
    response_types_supported: ['code'],
    // `client_credentials` is how a role identity signs, with no person in the
    // flow at all (PEEK-34). Advertised because a relying party configuring
    // itself from discovery should not have to read our source to find it.
    // `refresh_token` is what lets a browser app survive its access token
    // expiring without a top-level redirect (PEEK-108).
    grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token'],
    // S256 only. `plain` is permitted by RFC 7636 and protects nothing an
    // interceptor cannot replay, so advertising it would only invite a client
    // to choose it.
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: [ALG],
    claims_supported: ['sub', 'aud', 'iss', 'exp', 'iat', 'act', 'sid'],
  }
}
