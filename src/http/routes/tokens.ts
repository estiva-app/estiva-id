/**
 * Token issuance and discovery (PEEK-29).
 *
 *   * `GET /.well-known/openid-configuration` and `GET /.well-known/jwks.json`
 *     — what a relying party resolves. `convex/auth.config.ts` takes a `domain`
 *     plus an `applicationID` and finds JWKS from discovery, the same way a
 *     Clerk or Auth0 integration does.
 *   * `POST /token` — the browser-side handoff, in its minimal form: exchange a
 *     session on this origin for a short-lived JWT scoped to one app.
 *
 * **Two grants, and both are needed.**
 *
 *   * `authorization_code` with PKCE (PEEK-90) — how an app on another origin
 *     gets a token. The session cookie is `SameSite=Lax`, so it is not sent on
 *     a cross-site `fetch` at all; relaxing that on the origin holding every
 *     custodied key is not worth it, so the redirect flow is the answer.
 *
 *     This endpoint *does* send CORS headers, and that is not a contradiction:
 *     they carry no `Allow-Credentials`, so the cookie still cannot be used
 *     from another origin. What they permit is a public client reading the
 *     response to a request it authenticated with a code and a PKCE verifier —
 *     credentials it already holds. Discovering that distinction cost one
 *     failed exchange; see the middleware below.
 *   * The original session grant — kept, because the account page is served
 *     from this very origin and making it round-trip through a redirect to talk
 *     to its own backend would be ceremony with no security to show for it.
 *
 * The body's shape selects the grant: `{ grantType: 'authorization_code', … }`
 * takes the new path, anything else takes the session path. That keeps the
 * existing callers working unchanged.
 */
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { findAppPolicy } from '../../domain/apps.js'
import { ownerAttestation } from '../../domain/attestation.js'
import { recordAudit } from '../../domain/audit.js'
import { redeemAuthorizationCode } from '../../domain/authorization.js'
import { type TokenDelegate, discoveryDocument, issueToken, publicJwks } from '../../domain/jwt.js'
import { getActivePubkey } from '../../domain/keys.js'
import { issueRefreshToken, redeemRefreshToken } from '../../domain/refresh.js'
import { authenticateServiceCredential } from '../../domain/roles.js'
import { type Session, findSessionById, touchSession } from '../../domain/sessions.js'
import { findUserById } from '../../domain/users.js'
import { AppError, badRequest, forbidden, unauthenticated } from '../../errors.js'
import type { AuthTag } from '../../nostr/nip-oa.js'
import type { AppEnv } from '../app.js'
import { allowOrigin, preflight } from '../cors.js'

const codeGrantSchema = z.object({
  grantType: z.literal('authorization_code'),
  code: z.string().min(1),
  clientId: z.string().min(1),
  redirectUri: z.string().url(),
  codeVerifier: z.string().min(43).max(128),
})

/**
 * The client-credentials grant, for role identities (PEEK-34).
 *
 * No `redirectUri` and no `codeVerifier`: there is no browser and no person to
 * send anywhere. The app *is* the principal's custodian, which is exactly why
 * it must present a secret — and why only a server-side client may hold one.
 */
const serviceGrantSchema = z.object({
  grantType: z.literal('client_credentials'),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
})

/**
 * The refresh grant (PEEK-108).
 *
 * No secret and no verifier: a public client has neither. The refresh token
 * *is* the credential, which is why it rotates on every use and why presenting
 * a spent one revokes the whole chain — see `domain/refresh.ts`.
 */
const refreshGrantSchema = z.object({
  grantType: z.literal('refresh_token'),
  refreshToken: z.string().min(1),
  clientId: z.string().min(1),
})

/**
 * The RFC 6749 §5.2 error a refusal answers with, when the request came in the
 * standard form format. The JSON format keeps this service's own error shape.
 */
type OAuthErrorCode =
  | 'invalid_request'
  | 'invalid_client'
  | 'invalid_grant'
  | 'unsupported_grant_type'

/** A refusal that also names its RFC 6749 §5.2 error. */
class TokenRefusal extends AppError {
  constructor(
    error: AppError,
    readonly oauth: OAuthErrorCode,
  ) {
    super(error.code, error.message, error.detail)
  }
}

const refused = (error: AppError, oauth: OAuthErrorCode) => new TokenRefusal(error, oauth)

/*
  The refusals every grant shares. An unknown or disabled app is
  `invalid_client` (RFC 6749 §5.2: "unknown client"). An offboarded person, or
  one with no key, is `invalid_grant`: the grant they gave has been revoked.
*/
const appRefused = () => refused(forbidden('Unknown or disabled app'), 'invalid_client')
const personRefused = () => refused(forbidden('That identity is no longer active'), 'invalid_grant')
const noKey = () => refused(forbidden('No active key for this identity'), 'invalid_grant')
const grantRefused = () => refused(badRequest('invalid_grant'), 'invalid_grant')

/** The form's parameter names (RFC 6749 §4.1.3, §4.4.2, §6; RFC 7636 §4.5), and ours. */
const FORM_FIELDS = {
  grant_type: 'grantType',
  code: 'code',
  redirect_uri: 'redirectUri',
  code_verifier: 'codeVerifier',
  refresh_token: 'refreshToken',
  client_id: 'clientId',
  client_secret: 'clientSecret',
} as const

const FIELD_NAMES = Object.fromEntries(
  Object.entries(FORM_FIELDS).map(([form, ours]) => [ours, form]),
) as Record<string, string>

/**
 * Read an `application/x-www-form-urlencoded` body into the grant schemas'
 * names. A parameter with no value counts as absent and one sent twice is
 * refused (RFC 6749 §3.1); parameters this service does not use, such as
 * `scope`, are ignored.
 */
async function readForm(c: Context<AppEnv>): Promise<Record<string, string>> {
  const body: Record<string, string> = {}
  const seen = new Set<string>()
  for (const [name, value] of new URLSearchParams(await c.req.text())) {
    if (seen.has(name))
      throw refused(badRequest(`${name} is sent more than once`), 'invalid_request')
    seen.add(name)
    if (!Object.hasOwn(FORM_FIELDS, name) || value === '') continue
    body[FORM_FIELDS[name as keyof typeof FORM_FIELDS]] = value
  }
  return body
}

/**
 * `client_secret_basic` (RFC 6749 §2.3.1, which a server MUST support): the
 * client's id and secret, each form-urlencoded, in an `Authorization: Basic`
 * header. Moved into the body's names; a client using two methods at once is
 * refused (§2.3).
 */
function readBasicAuth(c: Context<AppEnv>, body: Record<string, string>): void {
  const header = c.req.header('authorization')
  if (!header) return
  const [scheme, encoded] = header.split(' ')
  const decoded =
    scheme?.toLowerCase() === 'basic' && encoded
      ? Buffer.from(encoded, 'base64').toString('utf8')
      : ''
  const colon = decoded.indexOf(':')
  if (colon < 1) throw refused(unauthenticated('Malformed client authentication'), 'invalid_client')
  const decode = (part: string) => decodeURIComponent(part.replace(/\+/g, ' '))
  let clientId: string
  let clientSecret: string
  try {
    clientId = decode(decoded.slice(0, colon))
    clientSecret = decode(decoded.slice(colon + 1))
  } catch {
    throw refused(unauthenticated('Malformed client authentication'), 'invalid_client')
  }
  if (body.clientSecret || (body.clientId && body.clientId !== clientId)) {
    throw refused(badRequest('Use one client authentication method'), 'invalid_request')
  }
  body.clientId = clientId
  body.clientSecret = clientSecret
}

/** A form request's answer to a refusal: RFC 6749 §5.2, `invalid_client` as 401. */
function oauthErrorResponse(c: Context<AppEnv>, error: AppError, oauth: OAuthErrorCode) {
  c.get('log')?.warn({ code: error.code, oauth, detail: error.detail }, error.message)
  const description = error.message === oauth ? undefined : error.message
  return c.json(
    { error: oauth, ...(description ? { error_description: description } : {}) },
    oauth === 'invalid_client' ? 401 : 400,
  )
}

/**
 * The token body every grant returns.
 *
 * `refresh_token` is present only where one was minted — the code and refresh
 * grants. The session grant is same-origin and the client-credentials grant has
 * a secret it can present again, so neither needs one, and issuing a long-lived
 * credential to a caller with no use for it is pure downside.
 *
 * ## `allowed_kinds`, and why it is here rather than nowhere
 *
 * The ceiling `/sign` enforces was knowable only to this service, so an app
 * discovered its own limits by attempting something and being refused at the
 * last step — after its own state had already changed. **Five features have
 * shipped that way** (PEEK-172): a Ship change from Peek, a resolution, a topic
 * rename, a topic delete, and an agent creating a topic. Every one of them was
 * locally correct; the row was written, the screen re-rendered, and only the
 * relay never heard. `src/db/seed.ts` carries the running account.
 *
 * A local success and a remote refusal are indistinguishable from inside an
 * app, which is what makes that failure quiet. Returning the ceiling makes it
 * answerable *before* the attempt: an agent can decline to advertise a tool it
 * cannot sign for, a UI can disable an action rather than performing it and
 * silently not publishing.
 *
 * **Not a secret.** It is a fact about the caller, the caller is authenticated,
 * and the caller is the one thing the fact is about. Withholding it protected
 * nothing and cost five debugging sessions.
 */
function tokenResponse(
  issued: { token: string; expiresIn: number; pubkey: string },
  allowedKinds: number[],
  extra: { refreshToken?: string; ownerAttestation?: AuthTag } = {},
) {
  return {
    access_token: issued.token,
    token_type: 'Bearer',
    expires_in: issued.expiresIn,
    pubkey: issued.pubkey,
    issuer: config().ISSUER_URL,
    allowed_kinds: allowedKinds,
    ...(extra.refreshToken ? { refresh_token: extra.refreshToken } : {}),
    ...(extra.ownerAttestation ? { owner_attestation: extra.ownerAttestation } : {}),
  }
}

/**
 * The `act` a token minted from this session carries, if a bot holds it
 * (PER-22). Every grant that starts from a session goes through here, so none
 * of them can mint a bot's token that looks like the person's.
 */
function tokenDelegate(session: Session): TokenDelegate | undefined {
  return session.delegate
    ? { clientId: session.delegate.clientId, sessionId: session.id }
    : undefined
}

/** The audit detail naming the bot, when there is one. */
function delegateDetail(delegate: TokenDelegate | undefined): { delegate?: string } {
  return delegate ? { delegate: delegate.clientId } : {}
}

export function tokenRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.get('/.well-known/openid-configuration', (c) => {
    // Cacheable: relying parties fetch this on cold start and it changes only
    // when the issuer does.
    c.header('cache-control', 'public, max-age=300')
    return c.json(discoveryDocument())
  })

  routes.get('/.well-known/jwks.json', async (c) => {
    c.header('cache-control', 'public, max-age=300')
    return c.json(await publicJwks())
  })

  /**
   * The code grant is used by a **public client in a browser on another
   * origin**, so the browser has to be allowed to read the response. Without
   * this the redirect completes, the code comes back, and the exchange dies at
   * the preflight — which is exactly what happened the first time Ship tried it.
   *
   * The rules, and why the session grant stays same-origin-only regardless, are
   * in `http/cors.ts`.
   */
  routes.options('/token', preflight('POST, OPTIONS', 'content-type'))

  /**
   * The grant is chosen by the body, not by a separate route, so relying
   * parties have one token endpoint to configure — which is also what
   * discovery advertises.
   *
   * `requireSession` cannot be middleware here: the code grant has no session
   * by definition, and a cross-origin caller has no cookie to send.
   */
  routes.post('/token', async (c) => {
    // Sets the header when the origin is registered; a same-origin request has
    // no Origin header and needs none.
    await allowOrigin(c)
    // RFC 6749 §5.1: an answer holding a token is never cached.
    c.header('cache-control', 'no-store')
    c.header('pragma', 'no-cache')

    /*
      The standard format only (record sign-in-is-plain-oauth): what any OAuth
      library sends, answered with RFC 6749 §5.2 errors. Estiva's own JSON
      format, and the cookie `{ clientId }` grant that came with it, are gone.
      why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/sign-in-is-plain-oauth.md
    */
    try {
      const mediaType = (c.req.header('content-type') ?? '').split(';')[0]?.trim().toLowerCase()
      if (mediaType !== 'application/x-www-form-urlencoded') {
        throw refused(
          badRequest('Send the request as application/x-www-form-urlencoded (RFC 6749 §4)'),
          'invalid_request',
        )
      }
      return await formGrant(c)
    } catch (error) {
      if (error instanceof TokenRefusal) return oauthErrorResponse(c, error, error.oauth)
      if (error instanceof AppError && error.status === 400) {
        return oauthErrorResponse(c, error, 'invalid_request')
      }
      throw error
    }
  })

  /** A form request: the grant `grant_type` names, or the §5.2 error for it. */
  async function formGrant(c: Context<AppEnv>) {
    const body = await readForm(c)
    readBasicAuth(c, body)
    const grant = body.grantType
    const invalid = (failure: z.ZodError) => {
      const issues = failure.issues.map((issue) => ({
        path: issue.path.map((part) => FIELD_NAMES[String(part)] ?? String(part)).join('.'),
        message: issue.message,
      }))
      const names = [...new Set(issues.map((issue) => issue.path))].join(', ')
      return refused(
        badRequest(`Invalid ${grant} request: ${names}`, { issues }),
        'invalid_request',
      )
    }

    switch (grant) {
      case undefined:
        throw refused(badRequest('grant_type is required'), 'invalid_request')
      case 'authorization_code': {
        const parsed = codeGrantSchema.safeParse(body)
        if (!parsed.success) throw invalid(parsed.error)
        return exchangeAuthorizationCode(c, parsed.data)
      }
      case 'refresh_token': {
        const parsed = refreshGrantSchema.safeParse(body)
        if (!parsed.success) throw invalid(parsed.error)
        return exchangeRefreshToken(c, parsed.data)
      }
      case 'client_credentials': {
        // The secret in the body or in HTTP Basic (RFC 6749 §2.3.1).
        const parsed = serviceGrantSchema.safeParse(body)
        if (!parsed.success) throw invalid(parsed.error)
        return exchangeClientCredentials(c, parsed.data)
      }
      default:
        throw refused(badRequest(`grant_type ${grant} is not supported`), 'unsupported_grant_type')
    }
  }

  /**
   * `grant_type=authorization_code` — the cross-origin path (PEEK-90).
   *
   * Authentication here is the code plus the PKCE verifier, not a cookie. The
   * person proved who they were at `/authorize`; this proves the redeemer is
   * the same app that started the flow.
   *
   * **Every refusal is `invalid_grant` to the caller and specific in the audit
   * log.** Telling a redeemer whether a code was unknown, expired, already
   * used, or matched with the wrong verifier hands an attacker a probe; the
   * distinction matters to us, not to them.
   */
  async function exchangeAuthorizationCode(
    c: Context<AppEnv>,
    input: z.infer<typeof codeGrantSchema>,
  ) {
    const redemption = await redeemAuthorizationCode({
      code: input.code,
      clientId: input.clientId,
      redirectUri: input.redirectUri,
      codeVerifier: input.codeVerifier,
    })

    if (!redemption.ok) {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: input.clientId,
        action: 'token.exchange',
        outcome: 'refused',
        // `already_used` is a replay and worth alerting on one day; the others
        // are ordinary. Recording which is the whole point of a generic reply.
        detail: { reason: redemption.reason },
        requestId: c.get('requestId'),
      })
      throw grantRefused()
    }

    // The app was checked when the code was issued, but a code outlives that
    // check by up to a minute — long enough for an app to be disabled between
    // the two halves of the flow.
    const app = await findAppPolicy(redemption.clientId)
    if (!app || app.status !== 'active') throw appRefused()

    // Same reason the session grant checks: offboarding must take effect within
    // the JWT TTL, and a code issued a minute ago is not evidence of anything.
    const user = await findUserById(redemption.userId)
    if (!user || user.status !== 'active') {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: app.clientId,
        action: 'token.exchange',
        outcome: 'refused',
        detail: { reason: user ? `user_${user.status}` : 'user_missing' },
        requestId: c.get('requestId'),
      })
      throw personRefused()
    }

    const pubkey = await getActivePubkey(redemption.userId)
    if (!pubkey) throw noKey()

    /*
      Whether the session that approved this code was a bot's (PER-22). Looked
      up rather than carried on the code, so there is one place that says so —
      and a delegation revoked in the minute since `/authorize` ends here.
    */
    const approving = redemption.sessionId ? await findSessionById(redemption.sessionId) : undefined
    if (approving?.delegate && !approving.live) {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: app.clientId,
        action: 'token.exchange',
        outcome: 'refused',
        detail: { reason: 'delegation_ended', delegate: approving.delegate.clientId },
        requestId: c.get('requestId'),
      })
      throw grantRefused()
    }
    const delegate = approving ? tokenDelegate(approving) : undefined

    const issued = await issueToken({ pubkey, clientId: app.clientId, delegate })

    /**
     * A refresh token, so the access token above can be short again (PEEK-108).
     *
     * Absent when the code carried no session — a code written before that
     * column existed, which expires within a minute of the deploy. The app then
     * gets exactly the old behaviour rather than an error, which is what makes
     * this deployable without coordinating the two halves.
     */
    const refresh = redemption.sessionId
      ? await issueRefreshToken({
          clientId: app.clientId,
          userId: redemption.userId,
          sessionId: redemption.sessionId,
        })
      : null

    await recordAudit({
      actorType: 'app',
      actorUserId: redemption.userId,
      actorClientId: app.clientId,
      action: 'token.exchange',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: {
        expiresIn: issued.expiresIn,
        refresh: refresh !== null,
        ...delegateDetail(delegate),
      },
      requestId: c.get('requestId'),
    })

    return c.json(tokenResponse(issued, app.allowedKinds, { refreshToken: refresh?.refreshToken }))
  }

  /**
   * `grant_type=refresh_token` — keeping a session alive without a redirect.
   *
   * Before this, an access token expiring cost a browser app a top-level
   * navigation and everything on screen, because there was nothing to exchange.
   * The mitigation was an hour-long access token; this is what lets that go
   * back down.
   *
   * **Every refusal is `invalid_grant`, and the reason goes to the audit log**
   * — same posture as the code grant, for the same reason. But one of them is
   * not routine: `reused` means two parties presented the same token, and
   * `redeemRefreshToken` has already revoked the entire chain by the time this
   * runs. It is recorded as `error` rather than `refused` so it is greppable as
   * the security event it is.
   */
  async function exchangeRefreshToken(
    c: Context<AppEnv>,
    input: z.infer<typeof refreshGrantSchema>,
  ) {
    const redemption = await redeemRefreshToken({
      refreshToken: input.refreshToken,
      clientId: input.clientId,
    })

    if (!redemption.ok) {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: input.clientId,
        action: 'token.refresh',
        outcome: redemption.reason === 'reused' ? 'error' : 'refused',
        detail: { reason: redemption.reason },
        requestId: c.get('requestId'),
      })
      throw grantRefused()
    }

    // Re-checked on every refresh, not just at sign-in. A refresh grant that
    // skipped this would let a disabled app or an offboarded person keep
    // minting tokens for as long as the session lasts, which is exactly the
    // hole a long-lived credential is expected to close rather than open.
    const app = await findAppPolicy(input.clientId)
    if (!app || app.status !== 'active') throw appRefused()

    const user = await findUserById(redemption.userId)
    if (!user || user.status !== 'active') {
      await recordAudit({
        actorType: 'app',
        actorUserId: redemption.userId,
        actorClientId: input.clientId,
        action: 'token.refresh',
        outcome: 'refused',
        detail: { reason: user ? `user_${user.status}` : 'user_missing' },
        requestId: c.get('requestId'),
      })
      throw personRefused()
    }

    const pubkey = await getActivePubkey(redemption.userId)
    if (!pubkey) throw noKey()

    // `redeemRefreshToken` checked the session a moment ago; checked again,
    // because a delegation revoked in between must not refresh without `act`.
    const session = await findSessionById(redemption.sessionId)
    if (session?.delegate && !session.live) throw grantRefused()
    const delegate = session ? tokenDelegate(session) : undefined

    // Accepted: the renewal is a use, and the sign-in's 7-day idle end moves forward.
    await touchSession(redemption.sessionId)
    const issued = await issueToken({ pubkey, clientId: app.clientId, delegate })

    await recordAudit({
      actorType: 'app',
      actorUserId: redemption.userId,
      actorClientId: app.clientId,
      action: 'token.refresh',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: {
        expiresIn: issued.expiresIn,
        // A retry within 30 s, answered with the successor it already had.
        ...(redemption.retried ? { retried: true } : {}),
        ...delegateDetail(delegate),
      },
      requestId: c.get('requestId'),
    })

    return c.json(
      tokenResponse(issued, app.allowedKinds, { refreshToken: redemption.refreshToken }),
    )
  }

  /**
   * `grant_type=client_credentials` — how a bot signs (PEEK-34).
   *
   * The app authenticates as itself and receives a token for the role identity
   * it is registered to act as. There is no person anywhere in this flow, which
   * is the point: a role has nobody to sign in, and before this it could hold a
   * key it could never use.
   *
   * **The secret buys a ten-minute token, it is not one.** That keeps the same
   * TTL every other grant has, so offboarding a bot takes effect just as fast as
   * offboarding a person, and nothing long-lived travels on a signing request.
   *
   * Refusals are deliberately indistinguishable to the caller — unknown client,
   * wrong secret, public client, offboarded identity all answer the same. Which
   * one it was matters to us and is in the audit log; telling the caller turns
   * this endpoint into an oracle for enumerating credentials.
   */
  async function exchangeClientCredentials(
    c: Context<AppEnv>,
    input: z.infer<typeof serviceGrantSchema>,
  ) {
    const credential = await authenticateServiceCredential(input.clientId, input.clientSecret)
    if (!credential) {
      await recordAudit({
        actorType: 'app',
        actorClientId: input.clientId,
        action: 'token.issue',
        outcome: 'refused',
        detail: { reason: 'invalid_client', grant: 'client_credentials' },
        requestId: c.get('requestId'),
      })
      throw refused(unauthenticated('invalid_client'), 'invalid_client')
    }

    if (!credential.pubkey) {
      throw refused(forbidden('No active key for this identity'), 'invalid_client')
    }

    const issued = await issueToken({ pubkey: credential.pubkey, clientId: credential.clientId })

    /**
     * The NIP-OA owner attestation, on the one grant that can have an owner.
     *
     * Only a role identity is ownable — `users_owner_only_for_roles` in
     * migration 008 — and this is the only grant that issues a token for one,
     * so the other three would be asking a question whose answer is always
     * "none". A workspace-owned role (`Relay Operator`) gets `undefined` here
     * and the field is simply absent, which is the correct description of it.
     */
    const attestation = await ownerAttestation(credential.actsAsUserId)

    await recordAudit({
      actorType: 'app',
      // The identity acted for, not a person who acted — there is none. Recording
      // it is what lets the audit trail answer "what has this bot been doing".
      actorUserId: credential.actsAsUserId,
      actorClientId: credential.clientId,
      action: 'token.issue',
      outcome: 'success',
      subjectPubkey: credential.pubkey,
      detail: {
        expiresIn: issued.expiresIn,
        grant: 'client_credentials',
        // Whether the bot left with a way to prove who steers it. Recorded
        // because its absence is silent everywhere else: the token still
        // works, the agent still publishes, and only the relay's
        // `agent_owner_pubkey` staying null would ever show it.
        ownerAttested: attestation !== undefined,
      },
      requestId: c.get('requestId'),
    })

    return c.json(tokenResponse(issued, credential.allowedKinds, { ownerAttestation: attestation }))
  }

  return routes
}
