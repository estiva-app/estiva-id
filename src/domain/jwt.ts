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

const ALG = 'ES256'

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
  const existing = await queryOne<{ kid: string }>(
    "select kid from jwt_signing_keys where status = 'active'",
  )
  if (existing) return existing.kid

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

export async function issueToken(input: {
  pubkey: string
  clientId: string
}): Promise<IssuedToken> {
  const cfg = config()
  const { kid, key } = await loadActiveSigningKey()

  const token = await new SignJWT({})
    .setProtectedHeader({ alg: ALG, kid, typ: 'JWT' })
    .setIssuer(cfg.ISSUER_URL)
    .setSubject(input.pubkey)
    .setAudience(input.clientId)
    .setIssuedAt()
    .setExpirationTime(`${cfg.JWT_TTL_SECONDS}s`)
    .sign(key)

  return { token, expiresIn: cfg.JWT_TTL_SECONDS, pubkey: input.pubkey }
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

    return { pubkey: payload.sub, clientId: audience }
  } catch (error) {
    throw unauthenticated(`Invalid token: ${(error as Error).message}`)
  }
}

/**
 * OIDC discovery document.
 *
 * Not a general-purpose OpenID Provider — there is no authorization code flow
 * here. It advertises exactly what a relying party needs to find and trust the
 * JWKS, which is what `convex/auth.config.ts` resolves from `domain`.
 */
export function discoveryDocument(): Record<string, unknown> {
  const issuer = config().ISSUER_URL
  return {
    issuer,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    token_endpoint: `${issuer}/token`,
    response_types_supported: ['token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: [ALG],
    claims_supported: ['sub', 'aud', 'iss', 'exp', 'iat'],
  }
}
