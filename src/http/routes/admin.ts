/**
 * The admin console's read side (PEEK-64).
 *
 * "Who is in this workspace" had no answer for a human before this. The rest of
 * the admin surface hangs off it — offboarding in one action (PEEK-66) and
 * adding a person (PEEK-65) both start from a row on this list.
 *
 * Read-only, deliberately. Every mutation an admin might want here already
 * exists as a domain function with its own ticket, and adding writes to the
 * screen that first makes the state legible would mean shipping them before
 * anybody had looked at what the state actually is.
 */
import { Hono } from 'hono'
import { auditActions, effectiveLimit, listAudit } from '../../domain/audit-log.js'
import { listCredentialSummaries } from '../../domain/credentials.js'
import { getDirectoryEntry, listDirectory } from '../../domain/directory.js'
import { notFound } from '../../errors.js'
import type { AppEnv } from '../app.js'
import { adminOnly } from '../middleware/admin.js'

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

  return routes
}
