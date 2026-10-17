/**
 * Adding a person (PEEK-65).
 *
 * An admin fills in who they are; the service returns a link. No password is
 * created or sent, because there is no password in this design — the link's
 * only job is to authorise exactly one passkey enrolment.
 *
 * **No mailer, on purpose.** Stage 1 is internal, so the admin copies the link
 * into a DM. Same flow, no provider dependency, and the mailer arrives when
 * handing links over by hand gets annoying rather than as a prerequisite.
 *
 * ## The half that is not here
 *
 * Creating an identity does not grant relay access. The relay runs closed
 * (`BUZZ_REQUIRE_RELAY_MEMBERSHIP=true`), so a newly enrolled person cannot
 * publish their profile until an operator admits their pubkey — Buzz owns
 * admission and Estiva ID only observes it (PEEK-36). The response therefore
 * hands back the pubkey placeholder and says so; a one-action onboarding that
 * reaches both systems is PEEK-66's shape, not this one's.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { recordAudit } from '../../domain/audit.js'
import {
  INVITE_TTL_HOURS,
  createInvite,
  findInvite,
  listPendingInvites,
} from '../../domain/invites.js'
import { findUserByEmail } from '../../domain/users.js'
import { badRequest, conflict } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { adminGrant, adminOnly } from '../middleware/admin.js'

const createSchema = z.object({
  email: z.string().email(),
  displayName: z.string().trim().max(200).optional(),
  handle: z
    .string()
    .trim()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9\-_.]+$/i, 'a-z, 0-9, dot, dash and underscore only')
    .optional(),
  role: z.enum(['admin', 'member']).optional(),
})

export function inviteRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  routes.post('/invites', ...adminGrant, async (c) => {
    const { userId } = c.get('session')

    const parsed = createSchema.safeParse(await c.req.json().catch(() => null))
    if (!parsed.success) {
      throw badRequest('Invalid invite', {
        issues: parsed.error.issues.map((issue) => ({
          path: issue.path.join('.'),
          message: issue.message,
        })),
      })
    }

    // An address that can already sign in does not need an invite, and issuing
    // one would imply a second identity for the same person — the opposite of
    // what this project is for.
    const existing = await findUserByEmail(parsed.data.email)
    if (existing) throw conflict('Someone with that email already exists')

    const invite = await createInvite({
      email: parsed.data.email,
      displayName: parsed.data.displayName,
      handle: parsed.data.handle?.toLowerCase(),
      role: parsed.data.role ?? 'member',
      createdBy: userId,
    })

    await recordAudit({
      actorType: 'user',
      actorUserId: userId,
      action: 'invite.create',
      outcome: 'success',
      // Never the token: the audit log is read by more people than the invite
      // is meant for, and it is a bearer credential.
      detail: { inviteId: invite.id, email: invite.email, role: invite.role },
      requestId: c.get('requestId'),
    })

    return c.json(
      {
        id: invite.id,
        email: invite.email,
        displayName: invite.displayName,
        handle: invite.handle,
        role: invite.role,
        expiresAt: invite.expiresAt.toISOString(),
        /** Shown once. Only its hash is stored, so this cannot be re-read. */
        url: `${config().ISSUER_URL}/?invite=${invite.token}`,
        expiresInHours: INVITE_TTL_HOURS,
      },
      201,
    )
  })

  /** Outstanding invites, so a half-onboarded person is visible (PEEK-64). */
  routes.get('/invites', ...adminOnly, async (c) => {
    const invites = await listPendingInvites()
    return c.json({
      invites: invites.map((invite) => ({
        id: invite.id,
        email: invite.email,
        displayName: invite.displayName,
        handle: invite.handle,
        role: invite.role,
        expiresAt: invite.expiresAt.toISOString(),
        /** True once somebody opened the link but never finished enrolling. */
        started: invite.claimedUserId !== null,
      })),
    })
  })

  /**
   * What the enrolment screen needs to render, before anybody is signed in.
   *
   * Public by necessity — the person holding the link has no session yet, which
   * is the entire point of the link. It reveals only what the admin already put
   * in the invite they were sent, and a wrong token reveals nothing at all.
   */
  routes.get('/invites/:token', async (c) => {
    const lookup = await findInvite(c.req.param('token'))
    if (!lookup.ok) {
      // 404 for all three, and the reason in the body. Distinguishing by status
      // would let a caller probe which tokens exist.
      return c.json({ valid: false, reason: lookup.reason }, 404)
    }
    return c.json({
      valid: true,
      email: lookup.invite.email,
      displayName: lookup.invite.displayName,
      handle: lookup.invite.handle,
      expiresAt: lookup.invite.expiresAt.toISOString(),
    })
  })

  return routes
}
