/**
 * Passkey registration and login (PEEK-26).
 *
 * Four ceremonies:
 *
 *   * `POST /auth/register/options` + `/verify` — a new person enrols.
 *   * `POST /auth/login/options` + `/verify` — an existing person signs in.
 *   * `POST /auth/credentials/options` + `/verify` — an **already signed-in**
 *     person adds another passkey. This is how a second device is enrolled, and
 *     why losing a laptop is an inconvenience rather than an identity loss.
 *   * `GET`/`DELETE /me/credentials` — see and revoke your own.
 *
 * Login is usernameless: options carry no `allowCredentials`, so the
 * authenticator offers whatever discoverable credential it holds for this RP.
 * That is why registration asks for `residentKey: 'required'`.
 */
import {
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server'
import { isoBase64URL } from '@simplewebauthn/server/helpers'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { z } from 'zod'
import { config } from '../../config.js'
import { recordAudit } from '../../domain/audit.js'
import { consumeChallenge, storeChallenge } from '../../domain/challenges.js'
import {
  countActiveCredentials,
  findActiveCredential,
  insertCredential,
  listActiveCredentials,
  listCredentialSummaries,
  ownsActiveCredential,
  recordCredentialUse,
  revokeCredential,
} from '../../domain/credentials.js'
import { getActivePubkey } from '../../domain/keys.js'
import {
  SESSION_COOKIE,
  createSession,
  revokeOtherSessions,
  revokeSession,
} from '../../domain/sessions.js'
import { createUserWithKey, findUserByEmail, findUserById } from '../../domain/users.js'
import { badRequest, conflict, forbidden, notFound, unauthenticated } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { requireSession } from '../middleware/session.js'

const registerSchema = z.object({
  email: z.string().email(),
  displayName: z.string().min(1).max(120).optional(),
})

/**
 * The challenge the authenticator actually signed over.
 *
 * Taken from `clientDataJSON` rather than trusted from the request body, then
 * looked up in the database — a challenge this service never issued has no row,
 * so `consumeChallenge` refuses it.
 */
function challengeFromClientData(clientDataJSON: string): string {
  let parsed: unknown
  try {
    parsed = JSON.parse(new TextDecoder().decode(isoBase64URL.toBuffer(clientDataJSON)))
  } catch {
    throw badRequest('Malformed clientDataJSON')
  }
  const challenge = (parsed as { challenge?: unknown }).challenge
  if (typeof challenge !== 'string') throw badRequest('clientDataJSON carries no challenge')
  return challenge
}

function setSessionCookie(c: Context<AppEnv>, token: string): void {
  const cfg = config()
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'Lax',
    secure: cfg.NODE_ENV === 'production',
    path: '/',
    maxAge: cfg.SESSION_TTL_SECONDS,
  })
}

export function authRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()
  const cfg = config()

  // --- Registration -------------------------------------------------------

  routes.post('/auth/register/options', async (c) => {
    const body = registerSchema.safeParse(await c.req.json().catch(() => ({})))
    if (!body.success) throw badRequest('email is required', { issues: body.error.issues })

    const existing = await findUserByEmail(body.data.email)
    if (existing && (await countActiveCredentials(existing.id)) > 0) {
      throw conflict('That email is already registered. Sign in instead.')
    }

    // Reuse an account whose enrolment was abandoned, rather than stranding the
    // address on a user row that can never be signed into.
    const user =
      existing ??
      (await createUserWithKey({ email: body.data.email, displayName: body.data.displayName }))

    const options = await generateRegistrationOptions({
      rpName: cfg.RP_NAME,
      rpID: cfg.RP_ID,
      userID: new TextEncoder().encode(user.id),
      userName: user.email ?? user.id,
      userDisplayName: user.display_name ?? user.email ?? user.id,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    })

    await storeChallenge({
      challenge: options.challenge,
      ceremony: 'registration',
      userId: user.id,
    })
    return c.json(options)
  })

  routes.post('/auth/register/verify', async (c) => {
    const response = (await c.req.json().catch(() => null)) as RegistrationResponseJSON | null
    if (!response?.response?.clientDataJSON) throw badRequest('Missing registration response')

    const challenge = challengeFromClientData(response.response.clientDataJSON)
    const claimed = await consumeChallenge(challenge, 'registration')
    if (!claimed?.userId) throw badRequest('Unknown, expired or already-used challenge')

    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: cfg.RP_ORIGINS,
      expectedRPID: cfg.RP_ID,
    })
    if (!verification.verified) {
      await recordAudit({
        actorType: 'user',
        actorUserId: claimed.userId,
        action: 'passkey.register',
        outcome: 'refused',
        detail: { reason: 'verification_failed' },
        requestId: c.get('requestId'),
      })
      throw forbidden('Registration could not be verified')
    }

    const info = verification.registrationInfo
    const credentialRowId = await insertCredential({
      userId: claimed.userId,
      credentialId: info.credential.id,
      publicKey: info.credential.publicKey,
      signCount: info.credential.counter,
      transports: info.credential.transports ?? [],
      aaguid: info.aaguid,
      backedUp: info.credentialBackedUp,
      deviceType: info.credentialDeviceType,
    })

    const [pubkey, { token }] = await Promise.all([
      getActivePubkey(claimed.userId),
      createSession({
        userId: claimed.userId,
        credentialId: credentialRowId,
        userAgent: c.req.header('user-agent'),
      }),
    ])

    await recordAudit({
      actorType: 'user',
      actorUserId: claimed.userId,
      action: 'passkey.register',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { credentialRowId, deviceType: info.credentialDeviceType },
      requestId: c.get('requestId'),
    })

    setSessionCookie(c, token)
    return c.json({ verified: true, pubkey })
  })

  // --- Login --------------------------------------------------------------

  routes.post('/auth/login/options', async (c) => {
    const options = await generateAuthenticationOptions({
      rpID: cfg.RP_ID,
      userVerification: 'preferred',
    })
    await storeChallenge({ challenge: options.challenge, ceremony: 'authentication' })
    return c.json(options)
  })

  routes.post('/auth/login/verify', async (c) => {
    const response = (await c.req.json().catch(() => null)) as AuthenticationResponseJSON | null
    if (!response?.response?.clientDataJSON) throw badRequest('Missing authentication response')

    const challenge = challengeFromClientData(response.response.clientDataJSON)
    if (!(await consumeChallenge(challenge, 'authentication'))) {
      throw badRequest('Unknown, expired or already-used challenge')
    }

    const stored = await findActiveCredential(response.id)
    if (!stored) throw unauthenticated('Unrecognised or revoked credential')

    const user = await findUserById(stored.userId)
    if (!user) throw unauthenticated('Unrecognised credential')
    if (user.status !== 'active') {
      await recordAudit({
        actorType: 'user',
        actorUserId: user.id,
        action: 'session.create',
        outcome: 'refused',
        detail: { reason: `user_${user.status}` },
        requestId: c.get('requestId'),
      })
      throw forbidden('This account is not active')
    }

    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: cfg.RP_ORIGINS,
      expectedRPID: cfg.RP_ID,
      credential: {
        id: stored.credentialId,
        publicKey: stored.publicKey,
        counter: stored.signCount,
        transports: stored.transports as never,
      },
    })
    if (!verification.verified) {
      await recordAudit({
        actorType: 'user',
        actorUserId: user.id,
        action: 'session.create',
        outcome: 'refused',
        detail: { reason: 'verification_failed' },
        requestId: c.get('requestId'),
      })
      throw unauthenticated('Authentication could not be verified')
    }

    await recordCredentialUse(stored.id, verification.authenticationInfo.newCounter)
    const [pubkey, { token }] = await Promise.all([
      getActivePubkey(user.id),
      createSession({
        userId: user.id,
        credentialId: stored.id,
        userAgent: c.req.header('user-agent'),
      }),
    ])

    await recordAudit({
      actorType: 'user',
      actorUserId: user.id,
      action: 'session.create',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { credentialRowId: stored.id },
      requestId: c.get('requestId'),
    })

    setSessionCookie(c, token)
    return c.json({ verified: true, pubkey })
  })

  routes.post('/auth/logout', requireSession, async (c) => {
    const session = c.get('session')
    const token = getCookie(c, SESSION_COOKIE)
    if (token) await revokeSession(token)
    await recordAudit({
      actorType: 'user',
      actorUserId: session.userId,
      action: 'session.revoke',
      outcome: 'success',
      requestId: c.get('requestId'),
    })
    deleteCookie(c, SESSION_COOKIE, { path: '/' })
    return c.json({ ok: true })
  })

  // --- Adding a second passkey (requires an existing session) --------------

  routes.post('/auth/credentials/options', requireSession, async (c) => {
    const { userId } = c.get('session')
    const existing = await listActiveCredentials(userId)
    const user = await findUserById(userId)

    const options = await generateRegistrationOptions({
      rpName: cfg.RP_NAME,
      rpID: cfg.RP_ID,
      userID: new TextEncoder().encode(userId),
      userName: user?.email ?? userId,
      userDisplayName: user?.display_name ?? user?.email ?? userId,
      attestationType: 'none',
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      // Stops the same authenticator being enrolled twice, which would look
      // like two devices and offer the safety of one.
      excludeCredentials: existing.map((credential) => ({
        id: credential.credentialId,
        transports: credential.transports as never,
      })),
    })

    await storeChallenge({ challenge: options.challenge, ceremony: 'registration', userId })
    return c.json(options)
  })

  // --- Self-serve credential management -----------------------------------

  routes.get('/me', requireSession, async (c) => {
    const { userId } = c.get('session')
    const [user, pubkey] = await Promise.all([findUserById(userId), getActivePubkey(userId)])
    if (!user) throw notFound('User not found')
    return c.json({
      id: user.id,
      email: user.email,
      displayName: user.display_name,
      status: user.status,
      pubkey,
    })
  })

  routes.get('/me/credentials', requireSession, async (c) => {
    const { userId } = c.get('session')
    return c.json({ credentials: await listCredentialSummaries(userId) })
  })

  /**
   * Sign out every other device, keeping this one.
   *
   * The companion to revoking a lost passkey: revoking the credential stops it
   * being used to *authenticate* again, but any session it already minted stays
   * valid until it expires. Someone who has lost a laptop needs both, and only
   * this half is time-critical.
   */
  routes.post('/me/sessions/revoke-others', requireSession, async (c) => {
    const session = c.get('session')
    const revoked = await revokeOtherSessions(session.userId, session.id)

    await recordAudit({
      actorType: 'user',
      actorUserId: session.userId,
      action: 'session.revoke_others',
      outcome: 'success',
      detail: { revoked },
      requestId: c.get('requestId'),
    })
    return c.json({ revoked })
  })

  routes.delete('/me/credentials/:id', requireSession, async (c) => {
    const { userId } = c.get('session')
    const credentialRowId = c.req.param('id')

    // Ownership first. Otherwise revoking someone else's credential is refused
    // by the last-passkey rule below, which is both a confusing message and a
    // small disclosure about an account that is not yours.
    if (!(await ownsActiveCredential(userId, credentialRowId))) {
      throw notFound('No such credential')
    }

    // Revoking your only passkey locks you out of your own identity, and Stage 1
    // has no recovery flow yet. Refusing is kinder than a support incident.
    if ((await countActiveCredentials(userId)) <= 1) {
      throw conflict('Cannot revoke your only passkey. Enrol another device first.')
    }

    await revokeCredential(userId, credentialRowId)

    await recordAudit({
      actorType: 'user',
      actorUserId: userId,
      action: 'passkey.revoke',
      outcome: 'success',
      detail: { credentialRowId },
      requestId: c.get('requestId'),
    })
    return c.json({ ok: true })
  })

  return routes
}
