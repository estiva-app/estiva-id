/**
 * The device flow: a person's bot asks for a session as them, and they approve
 * it with a passkey (PER-22).
 *
 *     bot    POST /device/authorize        { clientId, clientSecret, label? }
 *            → { device_code, user_code, verification_uri(_complete), interval }
 *     person GET  /device/requests/:code   what is asking, for the approval screen
 *            POST /device/requests/:code/options   a challenge bound to this request
 *            POST /device/requests/:code/approve   a passkey assertion over it
 *            POST /device/requests/:code/deny
 *     bot    POST /device/token            { deviceCode, clientId, clientSecret }
 *            → { session_token, cookie_name, expires_at, pubkey, delegate_tag }
 *
 * RFC 8628's shape, not its wire format: the bot collects a **session**, not an
 * access token, because the consumer is a headless browser driving the real
 * apps, and they sign in through `/authorize` like anybody else. Error names on
 * `/device/token` are RFC 8628's so a client can follow the polling rules.
 *
 * The person's side:
 *
 *   * **Approval is a passkey ceremony of its own**, with a challenge stored on
 *     the request — a session cookie the person already holds approves nothing.
 *   * **Only the bot's owner can approve.** Checked against whoever the passkey
 *     belongs to, after the assertion verifies, so a code forwarded to anybody
 *     else is refused whatever they do with it.
 *
 * Also self-service, for the account page: `GET /me/delegations` and
 * `POST /me/delegations/:id/revoke`. Behind `requireSession`, so a delegated
 * session cannot list or revoke delegations — including its own siblings.
 */
import type { AuthenticationResponseJSON } from '@simplewebauthn/server'
import { generateAuthenticationOptions } from '@simplewebauthn/server'
import type { Context } from 'hono'
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { recordAudit } from '../../domain/audit.js'
import { consumeChallenge, storeChallenge } from '../../domain/challenges.js'
import { findActiveCredential, recordCredentialUse } from '../../domain/credentials.js'
import {
  activeOwnerOf,
  approveDeviceRequest,
  denyDeviceRequest,
  findDeviceRequest,
  listDelegations,
  normalizeUserCode,
  pollDeviceRequest,
  revokeDelegation,
  setApprovalChallenge,
  startDeviceAuthorization,
} from '../../domain/delegation.js'
import { getActivePubkey } from '../../domain/keys.js'
import { authenticateServiceCredential } from '../../domain/roles.js'
import { SESSION_COOKIE } from '../../domain/sessions.js'
import { findUserById } from '../../domain/users.js'
import {
  badRequest,
  conflict,
  forbidden,
  notFound,
  rateLimited,
  unauthenticated,
} from '../../errors.js'
import type { AppEnv } from '../app.js'
import { requireSession } from '../middleware/session.js'
import { createRateLimiter } from '../rate-limit.js'
import { challengeFromClientData, verifyAuthentication } from './auth.js'

const startSchema = z.object({
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
  label: z.string().trim().min(1).max(80).optional(),
})

const pollSchema = z.object({
  deviceCode: z.string().min(1),
  clientId: z.string().min(1),
  clientSecret: z.string().min(1),
})

/**
 * Looking a code up is the only unauthenticated read here. 20^8 codes that live
 * ten minutes cannot be enumerated at any rate, but an unbounded lookup is
 * still an oracle nobody needs; sixty a minute per client is far above a person
 * retyping a code.
 */
const lookupLimiter = createRateLimiter(60, 60_000)

/** Test seam — see `rate-limit.ts`. Not reachable over HTTP. */
export const resetDeviceRateLimitForTests = () => lookupLimiter.reset()

function checkLookupBudget(c: Context<AppEnv>): void {
  const client = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? 'direct'
  const budget = lookupLimiter.check(client)
  if (!budget.allowed) {
    c.header('retry-after', String(budget.retryAfterSeconds))
    throw rateLimited('Too many code lookups', { retryAfterSeconds: budget.retryAfterSeconds })
  }
}

/**
 * The request a code names, if it can still be acted on. Every refusal is the
 * same 404 to the caller: a person holding a lapsed code and a stranger
 * guessing one are told the same thing.
 */
async function pendingRequest(c: Context<AppEnv>) {
  checkLookupBudget(c)
  const userCode = normalizeUserCode(c.req.param('code') ?? '')
  const request = userCode ? await findDeviceRequest(userCode) : undefined
  if (!request || request.status !== 'pending' || request.expired) {
    throw notFound('That code is not valid, or has expired. Ask the bot for a new one.')
  }
  return request
}

export function deviceRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()
  const cfg = config()

  // --- The bot asks --------------------------------------------------------

  routes.post('/device/authorize', async (c) => {
    const parsed = startSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) throw badRequest('Expected { clientId, clientSecret, label? }')

    const credential = await authenticateServiceCredential(
      parsed.data.clientId,
      parsed.data.clientSecret,
    )
    // A workspace role has nobody it could be granted to act as; only a
    // personal bot can ask, and only for its owner.
    const ownerUserId = credential ? await activeOwnerOf(credential.actsAsUserId) : undefined
    if (!credential || !ownerUserId) {
      await recordAudit({
        actorType: 'app',
        actorClientId: parsed.data.clientId,
        action: 'delegation.request',
        outcome: 'refused',
        detail: { reason: credential ? 'no_active_owner' : 'invalid_client' },
        requestId: c.get('requestId'),
      })
      throw unauthenticated('invalid_client')
    }

    const started = await startDeviceAuthorization({
      clientId: credential.clientId,
      label: parsed.data.label,
    })

    await recordAudit({
      actorType: 'app',
      actorUserId: credential.actsAsUserId,
      actorClientId: credential.clientId,
      action: 'delegation.request',
      outcome: 'success',
      detail: { userCode: started.userCode, label: parsed.data.label ?? null },
      requestId: c.get('requestId'),
    })

    const verificationUri = `${cfg.ISSUER_URL}/device`
    return c.json({
      device_code: started.deviceCode,
      user_code: started.userCode,
      verification_uri: verificationUri,
      verification_uri_complete: `${verificationUri}?code=${started.userCode}`,
      expires_in: started.expiresIn,
      interval: started.interval,
    })
  })

  /**
   * The bot collects its session. RFC 8628 §3.5's errors, as `error` in a 400,
   * so an off-the-shelf polling loop behaves: keep going on
   * `authorization_pending`, back off on `slow_down`, stop on anything else.
   */
  routes.post('/device/token', async (c) => {
    const parsed = pollSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) throw badRequest('Expected { deviceCode, clientId, clientSecret }')

    // The secret again, not just the device code: a device code that leaked
    // from the bot's logs must not be enough to collect somebody's session.
    const credential = await authenticateServiceCredential(
      parsed.data.clientId,
      parsed.data.clientSecret,
    )
    if (!credential) throw unauthenticated('invalid_client')

    const result = await pollDeviceRequest({
      deviceCode: parsed.data.deviceCode,
      clientId: credential.clientId,
      userAgent: c.req.header('user-agent'),
    })

    if (!result.ok) {
      // Polling is noise; the outcomes that end a request are not.
      if (result.reason !== 'authorization_pending' && result.reason !== 'slow_down') {
        await recordAudit({
          actorType: 'app',
          actorUserId: credential.actsAsUserId,
          actorClientId: credential.clientId,
          action: 'delegation.collect',
          outcome: 'refused',
          detail: { reason: result.reason },
          requestId: c.get('requestId'),
        })
      }
      return c.json({ error: result.reason }, 400)
    }

    // Re-checked at the moment a session is minted, not only at approval: the
    // owner could have been offboarded in the minutes between.
    const [user, pubkey] = await Promise.all([
      findUserById(result.userId),
      getActivePubkey(result.userId),
    ])
    if (!user || user.status !== 'active' || !pubkey) {
      await recordAudit({
        actorType: 'app',
        actorUserId: result.userId,
        actorClientId: credential.clientId,
        action: 'delegation.collect',
        outcome: 'refused',
        detail: { reason: user ? `user_${user.status}` : 'user_missing' },
        requestId: c.get('requestId'),
      })
      throw forbidden('That identity is no longer active')
    }

    await recordAudit({
      actorType: 'app',
      actorUserId: result.userId,
      actorClientId: credential.clientId,
      action: 'delegation.collect',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: {
        sessionId: result.sessionId,
        tag: result.tag,
        expiresAt: result.expiresAt.toISOString(),
      },
      requestId: c.get('requestId'),
    })

    return c.json({
      session_token: result.sessionToken,
      cookie_name: SESSION_COOKIE,
      expires_at: result.expiresAt.toISOString(),
      pubkey,
      delegate_tag: result.tag,
    })
  })

  // --- The person approves -------------------------------------------------

  routes.get('/device/requests/:code', async (c) => {
    const request = await pendingRequest(c)
    const owner = request.ownerUserId ? await findUserById(request.ownerUserId) : undefined
    return c.json({
      userCode: request.userCode,
      botName: request.botName,
      clientId: request.clientId,
      label: request.label,
      // Whose passkey will be accepted — so somebody who is not the owner is
      // told before they try, not after.
      ownerDisplayName: owner?.display_name ?? null,
      expiresAt: request.expiresAt.toISOString(),
      sessionHours: Math.round(cfg.DELEGATED_SESSION_TTL_SECONDS / 3600),
    })
  })

  routes.post('/device/requests/:code/options', async (c) => {
    const request = await pendingRequest(c)
    const options = await generateAuthenticationOptions({
      rpID: cfg.RP_ID,
      userVerification: 'required',
    })
    await storeChallenge({
      challenge: options.challenge,
      ceremony: 'delegation',
      userId: request.ownerUserId ?? undefined,
    })
    await setApprovalChallenge(request.id, options.challenge)
    return c.json(options)
  })

  routes.post('/device/requests/:code/approve', async (c) => {
    const request = await pendingRequest(c)
    const response = (await c.req.json().catch(() => null)) as AuthenticationResponseJSON | null
    if (!response?.response?.clientDataJSON) throw badRequest('Missing authentication response')

    const challenge = challengeFromClientData(response.response.clientDataJSON)
    // Both bindings: the challenge must be one this service issued for an
    // approval, and the one issued for *this* request.
    if (
      request.approvalChallenge !== challenge ||
      !(await consumeChallenge(challenge, 'delegation'))
    ) {
      throw badRequest('Unknown, expired or already-used challenge')
    }

    const refuse = async (reason: string, userId?: string) => {
      await recordAudit({
        actorType: 'user',
        actorUserId: userId,
        actorClientId: request.clientId,
        action: 'delegation.approve',
        outcome: 'refused',
        detail: { reason, userCode: request.userCode },
        requestId: c.get('requestId'),
      })
    }

    const stored = await findActiveCredential(response.id)
    if (!stored) {
      await refuse('unknown_credential')
      throw unauthenticated('Unrecognised or revoked credential')
    }

    const verification = await verifyAuthentication({
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
      await refuse('verification_failed', stored.userId)
      throw unauthenticated('Authentication could not be verified')
    }
    await recordCredentialUse(stored.id, verification.authenticationInfo.newCounter)

    // After verification, so this answers "is the person who just proved
    // themselves the owner" — not "does this credential id claim to be".
    if (stored.userId !== request.ownerUserId) {
      await refuse('not_the_owner', stored.userId)
      throw forbidden('Only the person this bot belongs to can approve it')
    }

    const user = await findUserById(stored.userId)
    if (!user || user.status !== 'active') {
      await refuse(user ? `user_${user.status}` : 'user_missing', stored.userId)
      throw forbidden('That identity is no longer active')
    }

    if (
      !(await approveDeviceRequest({
        requestId: request.id,
        userId: stored.userId,
        credentialRowId: stored.id,
      }))
    ) {
      throw conflict('That request was already answered')
    }

    await recordAudit({
      actorType: 'user',
      actorUserId: stored.userId,
      actorClientId: request.clientId,
      action: 'delegation.approve',
      outcome: 'success',
      subjectPubkey: (await getActivePubkey(stored.userId)) ?? undefined,
      detail: { userCode: request.userCode, credentialRowId: stored.id, label: request.label },
      requestId: c.get('requestId'),
    })

    return c.json({ approved: true, botName: request.botName })
  })

  routes.post('/device/requests/:code/deny', async (c) => {
    const request = await pendingRequest(c)
    await denyDeviceRequest(request.id)
    await recordAudit({
      actorType: 'user',
      actorClientId: request.clientId,
      action: 'delegation.deny',
      outcome: 'success',
      detail: { userCode: request.userCode },
      requestId: c.get('requestId'),
    })
    return c.json({ denied: true })
  })

  // --- The person reviews and revokes -------------------------------------

  routes.get('/me/delegations', requireSession, async (c) => {
    const { userId } = c.get('session')
    return c.json({ delegations: await listDelegations(userId) })
  })

  routes.post('/me/delegations/:id/revoke', requireSession, async (c) => {
    const { userId } = c.get('session')
    const sessionId = c.req.param('id')
    if (!z.string().uuid().safeParse(sessionId).success) throw notFound('No such delegation')

    const revoked = await revokeDelegation(userId, sessionId)
    if (!revoked) throw notFound('No such delegation')

    await recordAudit({
      actorType: 'user',
      actorUserId: userId,
      actorClientId: revoked.clientId,
      action: 'delegation.revoke',
      outcome: 'success',
      subjectPubkey: (await getActivePubkey(userId)) ?? undefined,
      detail: { sessionId },
      requestId: c.get('requestId'),
    })
    return c.json({ revoked: true })
  })

  return routes
}
