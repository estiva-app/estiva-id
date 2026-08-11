/**
 * The admin console's read side (PEEK-64).
 *
 * "Who is in this workspace" had no answer for a human before this. The rest of
 * the admin surface hangs off it — offboarding in one action (PEEK-66) and
 * adding a person (PEEK-65) both start from a row on this list.
 *
 * Read-first, and still nearly read-only. The list, the person and the audit
 * trail were built before any write, so that the screen making the state legible
 * shipped before anything that changes it.
 *
 * **One write now exists: offboarding** (PEEK-66). It earned the exception by
 * being the operation a half-completed checklist makes dangerous — the case
 * where doing it in one action is the whole point. Other mutations an admin
 * might want still live as domain functions with their own tickets.
 */
import { Hono } from 'hono'
import { z } from 'zod'
import { config } from '../../config.js'
import { auditActions, effectiveLimit, listAudit } from '../../domain/audit-log.js'
import { recordAudit } from '../../domain/audit.js'
import { listCredentialSummaries } from '../../domain/credentials.js'
import { getDirectoryEntry, listDirectory } from '../../domain/directory.js'
import { getActivePubkey } from '../../domain/keys.js'
import { AlreadyOffboarded, NoSuchPerson, offboardPerson } from '../../domain/offboarding.js'
import { RecoveryRefused, createRecovery } from '../../domain/recovery.js'
import { RoleRefused, createRoleIdentity, issueServiceCredential } from '../../domain/roles.js'
import { badRequest, conflict, notFound } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { adminOnly } from '../middleware/admin.js'

const createRoleSchema = z.object({
  displayName: z.string().min(1).max(200),
  email: z.string().email().optional(),
})

const credentialSchema = z.object({
  clientId: z
    .string()
    .min(1)
    .max(100)
    // The same shape the seeded apps use. A client id with spaces or a slash
    // would work everywhere except in the places it gets embedded in a URL.
    .regex(/^[a-z0-9][a-z0-9-]*$/, 'Lowercase letters, digits and dashes'),
  name: z.string().min(1).max(200),
  allowedKinds: z.array(z.number().int().nonnegative()).max(50),
})

export function adminRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>()

  /**
   * Everyone, in one list.
   *
   * Unpaginated. A Stage 1 workspace is a company, not a social network, and a
   * page control that never triggers is a control nobody has tested. It gains
   * one when a directory gets big enough to need it.
   */
  routes.get('/admin/people', ...adminOnly, async (c) => {
    return c.json({ people: await listDirectory() })
  })

  /**
   * The audit trail (PEEK-69).
   *
   * The table has been written since the service was built and read by nobody,
   * which made "custody is acceptable because misuse cannot happen unseen" an
   * argument about a table with no viewer. This is the viewer.
   *
   * Read-only and admin-only, with no delete: an audit log an admin can edit
   * answers a different question from the one it is here to answer.
   */
  routes.get('/admin/audit', ...adminOnly, async (c) => {
    const requested = c.req.query('limit') ? Number(c.req.query('limit')) : undefined
    const limit = effectiveLimit(requested)
    const entries = await listAudit({
      userId: c.req.query('person'),
      action: c.req.query('action'),
      before: c.req.query('before'),
      limit: requested,
    })

    return c.json({
      entries,
      // The id to pass as `before` for the next page — and **only when the page
      // came back full**. A short page is the end of the log, and offering
      // "show older" there is a button that answers with nothing.
      nextBefore: entries.length === limit ? (entries[entries.length - 1]?.id ?? null) : null,
      actions: await auditActions(),
    })
  })

  /**
   * One person, with their passkeys.
   *
   * The passkey list is the same summary shape a person sees for themselves —
   * labels and timestamps, never public keys or raw credential ids. An admin
   * needs to know a device exists and when it was last used; nothing here needs
   * the material itself, and a console that hands it over is a console worth
   * attacking.
   */
  routes.get('/admin/people/:id', ...adminOnly, async (c) => {
    const person = await getDirectoryEntry(c.req.param('id'))
    if (!person) throw notFound('No such person')

    return c.json({
      person,
      credentials: await listCredentialSummaries(person.id),
    })
  })

  /**
   * Offboard, in one action (PEEK-66).
   *
   * The first write on this surface, and it stays the only one for a reason:
   * offboarding is the operation where a half-completed checklist is a security
   * problem, so it is exactly the one worth making atomic.
   *
   * **It does three of the four steps and says so.** Revoking community
   * admission is Buzz's, and the response carries the command an operator still
   * has to run rather than reporting a success that is not true.
   */
  routes.post('/admin/people/:id/offboard', ...adminOnly, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const target = c.req.param('id')

    // An admin removing their own last route back in is a mistake nobody
    // recovers from without shell access — there is no recovery flow (PEEK-67).
    if (target === actorUserId) {
      throw badRequest('You cannot offboard yourself', { reason: 'self_offboard' })
    }

    try {
      return c.json(await offboardPerson(target, { actorUserId, requestId: c.get('requestId') }))
    } catch (error) {
      if (error instanceof NoSuchPerson) throw notFound('No such person')
      if (error instanceof AlreadyOffboarded) {
        throw conflict('That identity is already offboarded', { reason: 'already_offboarded' })
      }
      throw error
    }
  })

  /**
   * Issue a recovery link for somebody with no working passkey (PEEK-67).
   *
   * The link is returned once and never stored, so an admin who loses it issues
   * another — which supersedes the first, rather than leaving two live.
   *
   * **Self-service is refused.** An admin with a session can already add a
   * device from their own account page, so asking for a link for yourself means
   * either a misunderstanding or somebody with a stolen session widening their
   * foothold. The genuine case — the last admin locked out — cannot be solved
   * from inside the app at all and needs the same shell access that mints the
   * bootstrap invite.
   */
  routes.post('/admin/people/:id/recovery', ...adminOnly, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const target = c.req.param('id')

    if (target === actorUserId) {
      throw badRequest('Add a device from your account page instead', { reason: 'self_recovery' })
    }

    try {
      const recovery = await createRecovery({ userId: target, createdBy: actorUserId })

      await recordAudit({
        actorType: 'user',
        actorUserId,
        action: 'recovery.issue',
        outcome: 'success',
        /*
          The subject is the person the link opens, and recording it is what
          makes this visible *to them* rather than only to other admins.

          The audit log resolves its subject through `subject_pubkey` against
          `user_keys` — a `subjectUserId` in the detail is not indexed and
          nothing joins on it. Omitting this wrote a record that existed, said
          the right thing, and did not appear on the one screen it was written
          for, which is the whole point of the ticket.
        */
        subjectPubkey: (await getActivePubkey(target)) ?? undefined,
        // Never the token: the audit log is read by more admins than the link
        // is meant for, and it authorises taking over an identity.
        detail: { subjectUserId: target, expiresAt: recovery.expiresAt.toISOString() },
        requestId: c.get('requestId'),
      })

      return c.json({
        url: `${config().ISSUER_URL}/?recover=${recovery.token}`,
        expiresAt: recovery.expiresAt.toISOString(),
      })
    } catch (error) {
      if (error instanceof RecoveryRefused) {
        if (error.reason === 'no_such_person') throw notFound('No such person')
        // Recovering a suspended or offboarded identity would be a way back in
        // that bypasses the decision to take access away. Reinstating somebody
        // is a status change first, deliberately a separate act.
        throw conflict(error.message, { reason: error.reason })
      }
      throw error
    }
  })

  /**
   * Create a role identity (PEEK-34).
   *
   * **`role-identities`, not `roles`.** API routes mount before the UI
   * catch-all, so any client route sharing a literal segment with one is
   * swallowed by it — the trap that served the audit *JSON* to a browser on
   * PEEK-69. Leaving `/admin/roles` unclaimed keeps it available as a screen.
   */
  routes.post('/admin/role-identities', ...adminOnly, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const body = createRoleSchema.safeParse(await c.req.json().catch(() => null))
    if (!body.success) throw badRequest('Expected { displayName }')

    const identity = await createRoleIdentity({
      displayName: body.data.displayName,
      email: body.data.email ?? null,
    })

    await recordAudit({
      actorType: 'user',
      actorUserId,
      action: 'role.create',
      outcome: 'success',
      subjectPubkey: identity.pubkey,
      detail: { subjectUserId: identity.id, displayName: identity.display_name },
      requestId: c.get('requestId'),
    })

    return c.json({ identity: { id: identity.id, pubkey: identity.pubkey } })
  })

  /**
   * Mint the credential a bot authenticates with.
   *
   * The secret is returned once and stored only as a hash. Re-issuing replaces
   * it rather than adding a second, so rotation leaves exactly one live secret
   * — two would be a state somebody has to reason about during an incident.
   */
  routes.post('/admin/role-identities/:id/credential', ...adminOnly, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const body = credentialSchema.safeParse(await c.req.json().catch(() => null))
    if (!body.success) throw badRequest('Expected { clientId, name, allowedKinds }')

    try {
      const credential = await issueServiceCredential({
        userId: c.req.param('id'),
        clientId: body.data.clientId,
        name: body.data.name,
        allowedKinds: body.data.allowedKinds,
      })

      await recordAudit({
        actorType: 'user',
        actorUserId,
        action: 'role.credential',
        outcome: 'success',
        subjectPubkey: credential.pubkey ?? undefined,
        // Never the secret. It signs as the identity, and the audit log has a
        // wider readership than the one admin who minted it.
        detail: {
          subjectUserId: credential.actsAsUserId,
          clientId: credential.clientId,
          allowedKinds: body.data.allowedKinds,
        },
        requestId: c.get('requestId'),
      })

      return c.json({
        clientId: credential.clientId,
        clientSecret: credential.secret,
        pubkey: credential.pubkey,
      })
    } catch (error) {
      if (error instanceof RoleRefused) {
        if (error.reason === 'no_such_identity') throw notFound('No such identity')
        throw conflict(error.message, { reason: error.reason })
      }
      throw error
    }
  })

  return routes
}
