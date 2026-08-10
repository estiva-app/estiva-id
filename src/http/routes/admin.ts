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
