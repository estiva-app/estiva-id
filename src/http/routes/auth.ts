/**
 * Passkey registration and login (PEEK-26).
 *
 * Four ceremonies:
 *
 *   * `POST /auth/register/options` + `/auth/register/verify` — a new person
 *     enrols.
 *   * `POST /auth/login/options` + `/auth/login/verify` — an existing person
 *     signs in.
 *   * `POST /auth/recover/options` + `/auth/recover/verify` — somebody who lost
 *     every passkey enrols a new one against the identity they already had.
 *   * `POST /auth/credentials/options`, then **`/auth/register/verify`** — an
 *     **already signed-in** person adds another passkey. This is how a second
 *     device is enrolled, and why losing a laptop is an inconvenience rather
 *     than an identity loss.
 *
 * There is no `/auth/credentials/verify`: the add-a-passkey ceremony issues its
 * own options — session-scoped, and excluding what the person already has — but
 * then finishes through the registration verifier, because from that point the
 * two are the same act. Worth knowing before searching for a route that has
 * never existed.
 *
 * Self-service, not ceremonies: `GET`/`DELETE /me/credentials` — see and revoke
 * your own.
 *
 * Login is usernameless: options carry no `allowCredentials`, so the
 * authenticator offers whatever discoverable credential it holds for this RP.
 * That is why registration asks for `residentKey: 'required'`.
 */
import {
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
  type VerifiedAuthenticationResponse,
  type VerifiedRegistrationResponse,
  type VerifyAuthenticationResponseOpts,
  type VerifyRegistrationResponseOpts,
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
import { listAudit } from '../../domain/audit-log.js'
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
  revokeAllCredentialsExcept,
  revokeCredential,
} from '../../domain/credentials.js'
import {
  type InviteRejection,
  claimInvite,
  consumeInviteForUser,
  findInvite,
} from '../../domain/invites.js'
import { getActivePubkey } from '../../domain/keys.js'
import { publishProfile, saveProfile } from '../../domain/profile.js'
import {
  type RecoveryRejection,
  consumeRecoveryForUser,
  findRecovery,
} from '../../domain/recovery.js'
import { admitMember } from '../../domain/relay-membership.js'
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

/**
 * Why an invite was refused, in words the person holding the link can act on.
 *
 * Distinguishing the three is deliberate: "already used" and "expired" have
 * different fixes, and telling somebody their link is simply wrong when it has
 * in fact expired sends them looking for a typo.
 */
function inviteRefusal(reason: InviteRejection): string {
  if (reason === 'expired') return 'That invite has expired. Ask for a new one.'
  if (reason === 'consumed') return 'That invite has already been used. Sign in instead.'
  return 'That invite link is not valid.'
}

/**
 * The same courtesy for a recovery link (PEEK-67).
 *
 * `not_active` says the identity is no longer active rather than that the link
 * is broken, because those have opposite fixes: one is "ask for another link",
 * the other is "you were offboarded, and no link will help".
 */
function recoveryRefusal(reason: RecoveryRejection): string {
  if (reason === 'expired') return 'That recovery link has expired. Ask an admin for a new one.'
  if (reason === 'consumed') return 'That recovery link has already been used. Sign in instead.'
  if (reason === 'not_active') return 'That identity is no longer active.'
  return 'That recovery link is not valid.'
}

const recoverSchema = z.object({ recoveryToken: z.string().min(1) })

/**
 * What a person may see about their own account.
 *
 * An allowlist rather than a denylist, so a new audit action is invisible here
 * until somebody decides it should be shown. The opposite default leaks the
 * next action added by whoever was not thinking about this screen.
 */
const SELF_VISIBLE_ACTIONS = new Set([
  'recovery.issue',
  'recovery.complete',
  'passkey.register',
  'passkey.revoke',
  'session.create',
  'session.revoke',
  'user.offboard',
])

/**
 * Enrolment takes an invite, not an email (PEEK-65).
 *
 * The email and display name come from the invite the admin filled in, so an
 * invitee cannot quietly enrol as somebody else — a link that let you choose
 * your own address would be transferable to anyone.
 */
const registerSchema = z.object({
  inviteToken: z.string().min(1),
})

/**
 * What every ceremony here asks of the authenticator.
 *
 * `userVerification: 'required'` is not a preference we could soften. Both
 * `verify*Response` helpers default `requireUserVerification` to `true`, so a
 * ceremony without the UV flag is refused *after* the fact no matter what we ask
 * for. Asking for `'preferred'` therefore never widened what this service
 * accepts — it only moved the refusal to the worst possible place: the
 * authenticator, told UV was optional, was free to skip it, and the person found
 * out after their device had already minted and stored the credential.
 *
 * That is a passkey the browser keeps offering and this service has never heard
 * of. It cost a colleague two enrolment attempts on 2026-08-17, and left dead
 * passkeys on their device that they had to delete by hand.
 *
 * Requiring it up front makes the authenticator prompt instead, so a device that
 * cannot verify its user fails before anything is written down.
 */
const AUTHENTICATOR_SELECTION = {
  residentKey: 'required',
  userVerification: 'required',
} as const

/**
 * Both outcomes of a ceremony we will not accept, flattened into one.
 *
 * SimpleWebAuthn reports these two ways: a response failing a check comes back
 * as `verified: false`, while one that is structurally unacceptable — a clear UV
 * flag being the case we actually hit — *throws*. Only the first reaches the
 * refusal branches below, so the throwing half used to escape as an unhandled
 * 500 that wrote no audit record at all. The attempt vanished: the person saw a
 * generic server error and the audit log showed nothing between their sign-in
 * and their next request.
 *
 * The thrown message is kept and audited. It is the only description of what the
 * authenticator actually did wrong, and re-deriving it from a stack trace in the
 * container log is exactly the work this avoids.
 */
type Refused = { verified: false; refusal: string }

function refused(error: unknown): Refused {
  return { verified: false, refusal: error instanceof Error ? error.message : String(error) }
}

async function verifyRegistration(
  options: VerifyRegistrationResponseOpts,
): Promise<(VerifiedRegistrationResponse & { refusal?: string }) | Refused> {
  try {
    return await verifyRegistrationResponse(options)
  } catch (error) {
    return refused(error)
  }
}

async function verifyAuthentication(
  options: VerifyAuthenticationResponseOpts,
): Promise<(VerifiedAuthenticationResponse & { refusal?: string }) | Refused> {
  try {
    return await verifyAuthenticationResponse(options)
  } catch (error) {
    return refused(error)
  }
}

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
    if (!body.success) throw badRequest('An invite is required to enrol')

    // The gate. Registration was open until PEEK-65, which was survivable only
    // because a caller had to know the API — and the registration screen
    // removes exactly that barrier, so the two ship together.
    const lookup = await findInvite(body.data.inviteToken)
    if (!lookup.ok) throw forbidden(inviteRefusal(lookup.reason))
    const invite = lookup.invite

    const existing = await findUserByEmail(invite.email)
    if (existing && (await countActiveCredentials(existing.id)) > 0) {
      throw conflict('That email is already registered. Sign in instead.')
    }

    // Reuse an account whose enrolment was abandoned, rather than stranding the
    // address on a user row that can never be signed into. With invites this is
    // the ordinary path: dismissing the passkey prompt is the most common way
    // enrolment fails, and reopening the same link has to work.
    const user =
      existing ??
      (await createUserWithKey({
        email: invite.email,
        displayName: invite.displayName ?? undefined,
        role: invite.role,
      }))

    // Bound before enrolment can succeed, so /verify knows which invite to burn
    // and a retry lands on the same account.
    await claimInvite(invite.id, user.id)

    const options = await generateRegistrationOptions({
      rpName: cfg.RP_NAME,
      rpID: cfg.RP_ID,
      userID: new TextEncoder().encode(user.id),
      userName: user.email ?? user.id,
      userDisplayName: user.display_name ?? user.email ?? user.id,
      attestationType: 'none',
      authenticatorSelection: AUTHENTICATOR_SELECTION,
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

    const verification = await verifyRegistration({
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
        detail: { reason: 'verification_failed', refusal: verification.refusal },
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

    // Burned only now: a passkey exists, so the link has done its job. An
    // enrolment abandoned at the browser prompt leaves the invite live and the
    // person can reopen it.
    //
    // Returns undefined when this was a *second* device being enrolled rather
    // than a first — that path shares this route and has no invite.
    const consumed = await consumeInviteForUser(claimed.userId)

    // The handle the admin reserved, stored locally. Publishing it is deferred
    // until after admission below — a `kind:0` sent to a closed relay by a
    // pubkey it does not yet admit is simply dropped.
    if (consumed?.handle) {
      try {
        await saveProfile(claimed.userId, { handle: consumed.handle })
      } catch (error) {
        // Never fail enrolment over this: a passkey now exists, and refusing
        // here would strand an account somebody can already authenticate to.
        //
        // Logged rather than swallowed, because the two reasons differ sharply.
        // A handle taken between invite and enrolment is ordinary and the
        // person fixes it on their account page. An unset `COMMUNITY_HOST`
        // means *no* handle can ever be assigned — a deployment fault that
        // would otherwise be completely invisible.
        c.get('log').warn(
          { err: error, userId: claimed.userId, handle: consumed.handle },
          'could not claim the invited handle',
        )
      }
    }

    const [pubkey, { token }] = await Promise.all([
      getActivePubkey(claimed.userId),
      createSession({
        userId: claimed.userId,
        credentialId: credentialRowId,
        userAgent: c.req.header('user-agent'),
      }),
    ])

    /*
      Admission — the leg that made "add a person" three-quarters of an action
      (PEEK-65).

      Onboarding is two operations against two systems, and until PEEK-94 this
      service could only do the first. So somebody could be invited, enrol a
      passkey, sign in here, and still read nothing in either app: the relay runs
      closed and had never heard of their pubkey. The ticket's done-when is that
      a colleague signs into *both apps* having only touched a passkey, and this
      is the step that makes that true.

      Only on a first enrolment. A second device adds a passkey to an account
      whose pubkey was admitted the first time round, and re-asking would be a
      round trip to be told `alreadyInState`.

      **Failure does not fail enrolment.** The person has a working passkey and a
      session; refusing here would strand an account they can already
      authenticate to, over a step an admin can complete from the people list.
      It is recorded instead, and the row shows "Not admitted" until it is fixed
      — which is exactly what that column is for.
    */
    if (consumed && pubkey) {
      const admission = await admitMember(pubkey)
      await recordAudit({
        actorType: 'system',
        action: 'relay.admit',
        outcome: admission.ok ? 'success' : 'error',
        subjectPubkey: pubkey,
        detail: {
          subjectUserId: claimed.userId,
          viaEnrolment: true,
          ...(admission.ok ? {} : { reason: admission.reason }),
        },
        requestId: c.get('requestId'),
      })

      if (!admission.ok) {
        c.get('log').warn(
          { userId: claimed.userId, pubkey, reason: admission.reason },
          'enrolled but not admitted to the relay',
        )
      }

      /*
        Now the handle can mean something. Publishing before admission would
        have the relay drop the event, leaving a handle that resolves nowhere —
        which is why this was previously left for the account page's next save,
        a step nobody knew they had to take.
      */
      if (admission.ok && consumed.handle) {
        const outcome = await publishProfile(claimed.userId, { requestId: c.get('requestId') })
        if (!outcome.published) {
          c.get('log').warn(
            { userId: claimed.userId, handle: consumed.handle, reason: outcome.reason },
            'admitted but could not publish the invited handle',
          )
        }
      }
    }

    await recordAudit({
      actorType: 'user',
      actorUserId: claimed.userId,
      action: 'passkey.register',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { credentialRowId, deviceType: info.credentialDeviceType },
      requestId: c.get('requestId'),
    })

    /*
      This path signs the person in as well, and until PEEK-69 it recorded only
      the passkey — leaving the *first* session a person ever holds as the one
      session with no record. That is the worst hole to have: it is the session
      that establishes access, and "when did this account first get in" is the
      first question anybody asks of a log.
    */
    await recordAudit({
      actorType: 'user',
      actorUserId: claimed.userId,
      action: 'session.create',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { credentialRowId, viaEnrolment: true },
      requestId: c.get('requestId'),
    })

    setSessionCookie(c, token)
    return c.json({ verified: true, pubkey })
  })

  // --- Recovery (PEEK-67) -------------------------------------------------

  /**
   * What the link is for, before anybody touches an authenticator.
   *
   * Returns the email so the person can see whose account they are about to
   * take a passkey on — a link forwarded to the wrong colleague should be
   * obvious to them, not only to whoever issued it.
   */
  routes.get('/recovery/:token', async (c) => {
    const lookup = await findRecovery(c.req.param('token'))
    if (!lookup.ok) return c.json({ ok: false, reason: lookup.reason }, 404)

    const user = await findUserById(lookup.recovery.userId)
    if (!user) return c.json({ ok: false, reason: 'unknown' }, 404)

    return c.json({
      ok: true,
      recovery: {
        email: user.email,
        displayName: user.display_name,
        expiresAt: lookup.recovery.expiresAt.toISOString(),
      },
    })
  })

  routes.post('/auth/recover/options', async (c) => {
    const body = recoverSchema.safeParse(await c.req.json().catch(() => ({})))
    if (!body.success) throw badRequest('A recovery link is required')

    const lookup = await findRecovery(body.data.recoveryToken)
    if (!lookup.ok) throw forbidden(recoveryRefusal(lookup.reason))

    const user = await findUserById(lookup.recovery.userId)
    if (!user) throw notFound('No such identity')

    const options = await generateRegistrationOptions({
      rpName: cfg.RP_NAME,
      rpID: cfg.RP_ID,
      userID: new TextEncoder().encode(user.id),
      userName: user.email ?? user.id,
      userDisplayName: user.display_name ?? user.email ?? user.id,
      attestationType: 'none',
      authenticatorSelection: AUTHENTICATOR_SELECTION,
      // Deliberately not excluding the existing credentials. They are the ones
      // that were lost, and an authenticator that still holds one would refuse
      // the ceremony rather than replace it.
    })

    // `recovery`, not `registration`: only the route below retires the old
    // passkeys and burns the link, so this challenge must not be redeemable at
    // `/auth/register/verify`.
    await storeChallenge({ challenge: options.challenge, ceremony: 'recovery', userId: user.id })
    return c.json(options)
  })

  routes.post('/auth/recover/verify', async (c) => {
    const response = (await c.req.json().catch(() => null)) as RegistrationResponseJSON | null
    if (!response?.response?.clientDataJSON) throw badRequest('Missing registration response')

    const challenge = challengeFromClientData(response.response.clientDataJSON)
    const claimed = await consumeChallenge(challenge, 'recovery')
    if (!claimed?.userId) throw badRequest('Unknown, expired or already-used challenge')

    const verification = await verifyRegistration({
      response,
      expectedChallenge: challenge,
      expectedOrigin: cfg.RP_ORIGINS,
      expectedRPID: cfg.RP_ID,
    })
    if (!verification.verified) {
      await recordAudit({
        actorType: 'user',
        actorUserId: claimed.userId,
        action: 'recovery.complete',
        outcome: 'refused',
        detail: { reason: 'verification_failed', refusal: verification.refusal },
        requestId: c.get('requestId'),
      })
      throw forbidden('Registration could not be verified')
    }

    // Re-checked after the ceremony, because it is slow enough for an admin to
    // have offboarded somebody in the middle of it, and the later decision wins.
    const stillRecoverable = await findUserById(claimed.userId)
    if (!stillRecoverable || stillRecoverable.status !== 'active') {
      await recordAudit({
        actorType: 'user',
        actorUserId: claimed.userId,
        action: 'recovery.complete',
        outcome: 'refused',
        detail: { reason: 'not_active' },
        requestId: c.get('requestId'),
      })
      throw forbidden('That identity is no longer active')
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

    /*
      Every earlier passkey is retired, and this is the point of doing it here
      rather than at issuance.

      The premise is that the devices are gone — but "gone" usually means in
      somebody else's hands, and a found laptop whose passkey still works is the
      whole risk. Retiring at issuance would instead cut off a person who turns
      out to still have a working device and never redeems the link, which
      converts a support request into a lockout. Doing it the moment a
      replacement exists leaves no window in either direction.

      Ordered after the insert so a failure cannot leave nothing enrolled.
    */
    const passkeysRetired = await revokeAllCredentialsExcept(claimed.userId, credentialRowId)
    const consumed = await consumeRecoveryForUser(claimed.userId)

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
      action: 'recovery.complete',
      outcome: 'success',
      subjectPubkey: pubkey,
      // `pubkeyUnchanged` is recorded because it is the claim the whole feature
      // rests on, and a log that does not say it cannot later be used to show it.
      detail: { credentialRowId, passkeysRetired, consumed, pubkeyUnchanged: true },
      requestId: c.get('requestId'),
    })

    await recordAudit({
      actorType: 'user',
      actorUserId: claimed.userId,
      action: 'session.create',
      outcome: 'success',
      subjectPubkey: pubkey,
      detail: { credentialRowId, viaRecovery: true },
      requestId: c.get('requestId'),
    })

    setSessionCookie(c, token)
    return c.json({ verified: true, pubkey, passkeysRetired })
  })

  /**
   * Your own access history (PEEK-67).
   *
   * Recovery is mechanically identical to an admin taking somebody's account:
   * a new credential appears on an identity at an admin's instruction. Only the
   * trail distinguishes them, and a trail that only other admins can read does
   * not distinguish them *to the person it happened to* — who is the one with
   * the motive to notice.
   *
   * Narrowed to the actions that concern their access. This is not the admin
   * audit view with a filter: `/admin/audit` answers "what has happened here",
   * and this answers "what has happened to me", which is a smaller question
   * with a much larger audience.
   */
  routes.get('/me/security-events', requireSession, async (c) => {
    const { userId } = c.get('session')
    /*
      Filtered IN the query, and that is the whole bug this fixed.

      It used to ask for the newest 50 rows for this person and then keep the
      ones in `SELF_VISIBLE_ACTIONS`. But every `POST /sign` writes
      `sign.granted` and every `POST /token` writes `token.issue` /
      `token.exchange` / `token.refresh` — and Peek and Ship sign every message,
      reaction, edit and read-state publish. So an ordinary account's newest 50
      rows are entirely app traffic, all seven interesting actions are older than
      the window, and this answered `[]`.

      It looked intermittent rather than broken, which is why it survived: right
      after signing in a `session.create` sits in the window, so you see one
      entry — and a handful of actions later it is gone for good. Reported that
      way, as "I once or twice saw some logs but they disappear".
    */
    const entries = await listAudit({ userId, actions: [...SELF_VISIBLE_ACTIONS], limit: 50 })

    return c.json({
      events: entries
        .map((entry) => ({
          id: entry.id,
          occurredAt: entry.occurredAt,
          action: entry.action,
          outcome: entry.outcome,
          // Who did it, when that was somebody else. Naming the admin is the
          // point — "an admin" is not something a person can follow up on.
          actorEmail: entry.actorUserId === userId ? null : entry.actorEmail,
          actorDisplayName: entry.actorUserId === userId ? null : entry.actorDisplayName,
          bySomeoneElse: entry.actorUserId !== null && entry.actorUserId !== userId,
        })),
    })
  })

  // --- Login --------------------------------------------------------------

  routes.post('/auth/login/options', async (c) => {
    const options = await generateAuthenticationOptions({
      rpID: cfg.RP_ID,
      userVerification: 'required',
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
      await recordAudit({
        actorType: 'user',
        actorUserId: user.id,
        action: 'session.create',
        outcome: 'refused',
        detail: { reason: 'verification_failed', refusal: verification.refusal },
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
      authenticatorSelection: AUTHENTICATOR_SELECTION,
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
      // What they may do while active. The account page shows the way into the
      // admin console from this, so a member is never offered a door that
      // answers 403 — the check that matters still happens on the server.
      role: user.role,
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
