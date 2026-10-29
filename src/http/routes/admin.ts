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
import { admissionPort } from '../../domain/admission.js'
import { auditActions, effectiveLimit, listAudit } from '../../domain/audit-log.js'
import { recordAudit } from '../../domain/audit.js'
import { listCredentialSummaries } from '../../domain/credentials.js'
import { getDirectoryEntry, listDirectory } from '../../domain/directory.js'
import { getActivePubkey } from '../../domain/keys.js'
import {
  AlreadyOffboarded,
  NoSuchPerson,
  OperatorIdentity,
  offboardPerson,
} from '../../domain/offboarding.js'
import { publishProfile } from '../../domain/profile.js'
import { RecoveryRefused, createRecovery } from '../../domain/recovery.js'
import {
  NoSuchPerson as NoSuchReinstateTarget,
  NotOffboarded,
  reinstatePerson,
} from '../../domain/reinstate.js'
import { addMemberCommand, admitMember } from '../../domain/relay-membership.js'
import {
  RoleRefused,
  createRoleIdentity,
  issueServiceCredential,
  renameRoleIdentity,
  serviceCredentialFor,
  setCredentialKinds,
} from '../../domain/roles.js'
import { RoleChangeRefused, setUserRole } from '../../domain/users.js'
import { badRequest, conflict, notFound } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { adminGrant, adminOnly } from '../middleware/admin.js'

const createRoleSchema = z.object({
  displayName: z.string().min(1).max(200),
  email: z.string().email().optional(),
})

const roleSchema = z.object({ role: z.enum(['admin', 'member']) })

const renameRoleSchema = z.object({ displayName: z.string().min(1).max(200) })

const kindsSchema = z.object({
  allowedKinds: z.array(z.number().int().nonnegative()).max(50),
  // The file types a 45010 may carry; absent leaves them as they are.
  allowedTypes: z.array(z.string().min(1).max(100)).max(20).optional(),
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
  /**
   * Optional, and absent means "everything this deployment allows" rather than
   * "nothing" (PEEK-134).
   *
   * Empty is the fail-closed value in the column, which is right as a default
   * for a *row* and wrong as a default for a *form*: an admin who grants 27235
   * and says nothing here would get a bot allowed the one kind it needs and
   * refused every destination for it. `db/seed.ts` already resolves the same
   * ambiguity the same way for the seeded apps.
   */
  nip98UrlPrefixes: z.array(z.string().min(1).max(500)).max(20).optional(),
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
    const { entries, admissionUnknownReason } = await listDirectory()
    /*
      The reason rides beside the list, not on each row (PEEK-102).

      A grey "Relay: Not known" chip had four causes and one appearance, so
      offboarding the operator — which disabled admission for the whole
      workspace — produced a console indistinguishable from a healthy one. Every
      cause is workspace-wide, so this is one field rather than N copies of it.
    */
    return c.json({ people: entries, admissionUnknownReason })
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
      /*
        The bot's own credential, minus the secret. Never shown before — the
        client id was visible once, in the dialog that minted it, and after that
        only wherever somebody had pasted it. Reinstalling an extension asks for
        it again and there was nowhere to look.
      */
      serviceCredential: await serviceCredentialFor(person.id),
      // Same field as the list, for the same reason: a person whose admission
      // reads `unknown` deserves to be told whether that is about them or about
      // the workspace's ability to ask at all (PEEK-102).
      admissionUnknownReason: admissionPort().lastUnknownReason(),
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
      /*
        Refused for the same class of reason as self-offboarding, one scope up
        (PEEK-102). Offboarding the operator revokes its own relay admission and
        disables admission for the entire workspace — reads degrade to
        `unknown`, offboarding goes back to printing a command, and nothing says
        so. It happened on production during PEEK-94 QA.

        `badRequest` rather than `conflict`: nothing about the target's state is
        in the way. The request is refused on what that identity *is*, and the
        way to proceed is to repoint the config first.
      */
      if (error instanceof OperatorIdentity) {
        throw badRequest(error.message, { reason: 'operator_identity' })
      }
      throw error
    }
  })

  /**
   * Putting somebody back (PEEK-102).
   *
   * The counterpart offboarding never got. PEEK-66 built removal only, on the
   * reasoning that a half-finished *removal* is the dangerous direction — true,
   * and it left the reverse needing `update users set status='active'` against
   * production, which is how an ordinary mis-click became a database edit.
   *
   * **Not a relaxation of the recovery guard.** `createRecovery` refuses a
   * non-active identity so that a recovery link can never be a way back in
   * around offboarding. That stays. This is a separate, audited decision an
   * admin makes about an account, which is a different thing from a link
   * somebody holds.
   */
  routes.post('/admin/people/:id/reinstate', ...adminOnly, async (c) => {
    const { userId: actorUserId } = c.get('session')

    try {
      return c.json(
        await reinstatePerson(c.req.param('id'), {
          actorUserId,
          requestId: c.get('requestId'),
        }),
      )
    } catch (error) {
      if (error instanceof NoSuchReinstateTarget) throw notFound('No such person')
      if (error instanceof NotOffboarded) {
        throw conflict('That identity is not offboarded', { reason: 'not_offboarded' })
      }
      throw error
    }
  })

  /**
   * Admit somebody to the relay by hand (PEEK-65).
   *
   * Enrolment admits the pubkey itself, so this is the repair path rather than
   * the happy one: the relay was unreachable at the moment somebody finished
   * their passkey, and they are now `active` here and unable to read a thing in
   * either app. That state was previously only fixable over SSH, which meant
   * the people list could show "Not admitted" and offer nothing to do about it.
   *
   * Idempotent, because the relay treats an add of an existing member as
   * already-in-state and so does this — an admin pressing it twice is not an
   * error worth reporting.
   */
  routes.post('/admin/people/:id/admit', ...adminOnly, async (c) => {
    const target = c.req.param('id')
    const person = await getDirectoryEntry(target)
    if (!person) throw notFound('No such person')

    // Admitting somebody this service has already disabled would re-open the
    // half that offboarding closed, and leave the two systems disagreeing in
    // the dangerous direction. Reinstate them first, which does both.
    if (person.status !== 'active') {
      throw badRequest('Reinstate this identity before admitting it to the relay', {
        reason: 'not_active',
      })
    }
    if (!person.pubkey) {
      throw badRequest('That identity has no active key to admit', { reason: 'no_key' })
    }

    const result = await admitMember(person.pubkey)

    await recordAudit({
      actorType: 'user',
      actorUserId: c.get('session').userId,
      action: 'relay.admit',
      // `error` rather than `refused`: nothing declined this, the relay could
      // not be reached or could not be asked. A refusal would imply a decision.
      outcome: result.ok ? 'success' : 'error',
      subjectPubkey: person.pubkey,
      detail: {
        subjectUserId: target,
        alreadyAdmitted: result.alreadyInState === true,
        ...(result.ok ? {} : { reason: result.reason }),
      },
      requestId: c.get('requestId'),
    })

    /*
      Publish the profile now, and not a moment earlier (PEEK-165).

      Order is the whole of it: the relay drops a `kind:0` from a pubkey it does
      not admit, so publishing at creation leaves an identity whose name resolves
      nowhere. Enrolment already learned this — `auth.ts` publishes only once
      admission has succeeded, for exactly the same reason.

      Nothing did this for a **role identity**, which is why the Claude agent
      wrote to production for a day attributed to `b38fd268…` rather than a name:
      its display name lived in this database and never reached the relay, where
      every other app looks.

      Best-effort and non-fatal. Admission is the thing that was asked for and it
      succeeded; a profile that did not publish is a repair (`publish-profile`
      below), not a reason to report the admission as failed.
    */
    let profilePublished: boolean | undefined
    if (result.ok) {
      const outcome = await publishProfile(target, { requestId: c.get('requestId') })
      profilePublished = outcome.published
      if (!outcome.published) {
        c.get('log').warn(
          { userId: target, pubkey: person.pubkey, reason: outcome.reason },
          'admitted but could not publish the profile',
        )
      }
    }

    return c.json(
      result.ok
        ? {
            admitted: true,
            alreadyAdmitted: result.alreadyInState === true,
            profilePublished,
          }
        : {
            admitted: false,
            reason: result.reason ?? 'unknown',
            command: addMemberCommand(person.pubkey),
          },
    )
  })

  /**
   * Publish somebody's `kind:0` again (PEEK-165).
   *
   * The repair path, the same shape as `admit` above: admission publishes a
   * profile from now on, and this is how an identity that predates that gets
   * one without being offboarded and put back.
   *
   * Needed because the fix cannot be retroactive on its own — the agent that
   * has been writing to production already exists and is already admitted, so
   * no future admission will ever fire for it.
   *
   * `kind:0` is published here rather than through `/sign`, which refuses that
   * kind for every app. That refusal is what keeps two apps from each inventing
   * a name for one person (PEEK-31); this internal path is the one caller it
   * exists to leave room for, not a loophole in it.
   */
  routes.post('/admin/people/:id/publish-profile', ...adminOnly, async (c) => {
    const target = c.req.param('id')
    const person = await getDirectoryEntry(target)
    if (!person) throw notFound('No such person')
    if (!person.pubkey) {
      throw badRequest('That identity has no active key, so there is nothing to publish', {
        reason: 'no_key',
      })
    }

    const outcome = await publishProfile(target, { requestId: c.get('requestId') })
    if (outcome.published) return c.json({ published: true, eventId: outcome.eventId })

    /*
      Reported rather than thrown. The commonest reason is that the pubkey is
      not admitted, which is a different button on the same page — telling an
      admin which one is more use than a 500.
    */
    return c.json({ published: false, reason: outcome.reason ?? 'unknown' })
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
  /**
   * Grant or withdraw admin (PEEK-163).
   *
   * Admin used to be settable only at account creation, so a workspace whose
   * only admin left had no route back that did not involve `psql`. It is also
   * what unblocks onboarding a second person: everything else on this surface
   * is `adminOnly`, so the first person cannot share the work without this.
   *
   * **You cannot change your own role.** Demoting yourself is the one move
   * nobody recovers from without shell access — the same reasoning that refuses
   * self-offboarding, and here it doubles as the guarantee that the workspace
   * always keeps at least one admin: an admin may only demote somebody else,
   * which leaves themselves.
   *
   * Withdrawing is offered alongside granting deliberately. A grant with no
   * matching revoke means a mis-click is permanent, and permanent mistakes are
   * how a console teaches people to avoid it.
   */
  routes.post('/admin/people/:id/role', ...adminGrant, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const target = c.req.param('id')

    const body = roleSchema.safeParse(await c.req.json().catch(() => null))
    if (!body.success) throw badRequest('Expected { role: "admin" | "member" }')

    if (target === actorUserId) {
      throw badRequest('You cannot change your own role', { reason: 'self_role_change' })
    }

    try {
      const result = await setUserRole(target, body.data.role, {
        actorUserId,
        requestId: c.get('requestId'),
      })
      return c.json(result)
    } catch (error) {
      if (error instanceof RoleChangeRefused) {
        if (error.reason === 'no_such_person') throw notFound('No such person')
        throw badRequest(error.message, { reason: error.reason })
      }
      throw error
    }
  })

  routes.post('/admin/people/:id/recovery', ...adminGrant, async (c) => {
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
  routes.post('/admin/role-identities', ...adminGrant, async (c) => {
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
   * Rename a role identity, and republish the `kind:0` that carries the name.
   *
   * A role identity has no session and no passkey, so unlike a person it cannot
   * edit its own profile. Until this existed its name was fixed at creation
   * forever, which stopped mattering the moment an agent started posting into
   * team conversations: in a chat, a message from "Claude" reads as a colleague
   * and nothing says whose agent it is (PEEK-149).
   *
   * **The republish is the point, not a courtesy.** PEEK-165 was exactly this
   * gap in its first half — a display name captured here and never sent to the
   * relay, so every app rendered a hex string. Storing a new name without
   * publishing it would recreate that bug and look like it had worked.
   *
   * Reported rather than enforced, matching `PUT /me/profile`: the rename is
   * saved either way, and `published: false` makes a stale projection visible
   * instead of silent.
   */
  routes.patch('/admin/role-identities/:id', ...adminOnly, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const body = renameRoleSchema.safeParse(await c.req.json().catch(() => null))
    if (!body.success) throw badRequest('Expected { displayName }')

    let renamed: Awaited<ReturnType<typeof renameRoleIdentity>>
    try {
      renamed = await renameRoleIdentity({
        userId: c.req.param('id'),
        displayName: body.data.displayName,
      })
    } catch (error) {
      if (error instanceof RoleRefused) {
        if (error.reason === 'no_such_identity') throw notFound('No such identity')
        throw conflict(error.message, { reason: error.reason })
      }
      throw error
    }

    const outcome = await publishProfile(renamed.id, { requestId: c.get('requestId') })

    await recordAudit({
      actorType: 'user',
      actorUserId,
      action: 'role.rename',
      outcome: 'success',
      detail: {
        subjectUserId: renamed.id,
        from: renamed.previousDisplayName,
        to: renamed.displayName,
        // Whether the name actually reached the relay is the load-bearing fact
        // here, and the one somebody will want during an incident.
        published: outcome.published,
        ...(outcome.published ? {} : { publishError: outcome.reason ?? null }),
      },
      requestId: c.get('requestId'),
    })

    return c.json({
      identity: { id: renamed.id, displayName: renamed.displayName },
      published: outcome.published,
      eventId: outcome.eventId ?? null,
      ...(outcome.published ? {} : { publishError: outcome.reason ?? null }),
    })
  })

  /**
   * Change what a credential may sign, leaving the secret alone.
   *
   * The only previous route to a wider ceiling was re-issuing, which replaces
   * the secret and therefore breaks every copy of it — the file on a laptop,
   * the value in Claude Desktop's keychain, whatever somebody pasted into their
   * own setup. A capability change and a credential rotation are different
   * decisions, and making them one operation is why a needed widening gets put
   * off until something fails at `/sign` (PEEK-172 has the list).
   *
   * Admin-only, and that is the point rather than an inconvenience: PEEK-145
   * established there is no Folder boundary behind this, so `allowed_kinds` is
   * the entire containment for an agent. Granting a kind is a decision about
   * the whole workspace.
   *
   * why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/an-agent-signs-for-an-app-only-by-an-admin-grant.md
   */
  routes.patch('/admin/credentials/:clientId/kinds', ...adminGrant, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const body = kindsSchema.safeParse(await c.req.json().catch(() => null))
    if (!body.success) throw badRequest('Expected { allowedKinds }')

    let changed: Awaited<ReturnType<typeof setCredentialKinds>>
    try {
      changed = await setCredentialKinds({
        clientId: c.req.param('clientId'),
        allowedKinds: body.data.allowedKinds,
        allowedTypes: body.data.allowedTypes,
      })
    } catch (error) {
      if (error instanceof RoleRefused) {
        if (error.reason === 'no_such_identity') throw notFound('No such credential')
        throw conflict(error.message, { reason: error.reason })
      }
      throw error
    }

    await recordAudit({
      actorType: 'user',
      actorUserId,
      action: 'credential.kinds',
      outcome: 'success',
      detail: {
        clientId: changed.clientId,
        // Both sides, because "what was it before" is the question asked after
        // something stops working, and nothing else records it.
        from: changed.from,
        to: changed.to,
        typesFrom: changed.typesFrom,
        typesTo: changed.typesTo,
      },
      requestId: c.get('requestId'),
    })

    return c.json({ credential: changed })
  })

  /**
   * Mint the credential a bot authenticates with.
   *
   * The secret is returned once and stored only as a hash. Re-issuing replaces
   * it rather than adding a second, so rotation leaves exactly one live secret
   * — two would be a state somebody has to reason about during an incident.
   */
  routes.post('/admin/role-identities/:id/credential', ...adminGrant, async (c) => {
    const { userId: actorUserId } = c.get('session')
    const body = credentialSchema.safeParse(await c.req.json().catch(() => null))
    if (!body.success) throw badRequest('Expected { clientId, name, allowedKinds }')

    // Widening is still impossible — `evaluateSignPolicy` applies the
    // deployment bound as well — so the worst this default can do is grant a
    // bot every destination the deployment already permits. That is a far
    // better failure than a credential which looks minted and cannot read.
    const nip98UrlPrefixes =
      body.data.nip98UrlPrefixes && body.data.nip98UrlPrefixes.length > 0
        ? body.data.nip98UrlPrefixes
        : [...config().SIGN_NIP98_ALLOWED_URL_PREFIXES]

    try {
      const credential = await issueServiceCredential({
        userId: c.req.param('id'),
        clientId: body.data.clientId,
        name: body.data.name,
        allowedKinds: body.data.allowedKinds,
        nip98UrlPrefixes,
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
          // The resolved list, not what was asked for. Reading this back later
          // should say what the credential can actually do, and the default
          // above means those are not always the same thing.
          nip98UrlPrefixes,
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
