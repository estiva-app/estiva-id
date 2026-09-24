/**
 * Republish every active role account's kind:0, now carrying `"bot": true` (REM-3).
 *
 *   pnpm roles:republish            # who would be republished
 *   APPLY=1 pnpm roles:republish    # publish
 *
 * `publishProfile` marks a `role` account as NIP-24 `bot` from the next publish
 * on, but a role's profile is published when it is created or renamed, and the
 * events already on the relay say nothing — so Peek's People list, which reads
 * the marker to leave agents out, keeps listing them until each is re-emitted.
 * Built is not deployed, and deployed is not in effect; this is the step that
 * puts it in effect.
 *
 * kind:0 is replaceable, so running it twice publishes the same content twice
 * and changes nothing. It touches no row.
 *
 * On the box, like `republish-avatars.ts`:
 *
 *   docker compose run --rm -T -e APPLY=1 \
 *     estiva-id node dist/admin/republish-role-profiles.js
 */
import { config } from '../config.js'
import { closePool, query } from '../db/pool.js'
import { publishProfile } from '../domain/profile.js'

const APPLY = /^(1|true|yes|on)$/i.test(process.env.APPLY ?? '')

const out = (line = '') => process.stdout.write(`${line}\n`)

async function main(): Promise<void> {
  if (!config().RELAY_BRIDGE_URL)
    throw new Error('RELAY_BRIDGE_URL is not set — there is nothing to publish to')

  // Active only: an offboarded identity's kind:0 was republished deliberately
  // by `offboardPerson`, and re-signing it here would overrule that.
  const { rows } = await query<{ id: string; display_name: string | null }>(
    `select id, display_name
       from users
      where kind = 'role' and status = 'active'
      order by display_name nulls last`,
  )

  if (rows.length === 0) {
    out('Nothing to do — there is no active role account.')
    return
  }

  out(`${rows.length} role account${rows.length === 1 ? '' : 's'} to republish with "bot": true:`)
  for (const row of rows) out(`  ${row.display_name ?? row.id}`)
  out()

  if (!APPLY) {
    out('Dry run. Set APPLY=1 to publish.')
    return
  }

  let published = 0
  for (const row of rows) {
    // Per identity rather than aborting: one key that cannot be unsealed must
    // not leave the rest listed as people.
    const outcome = await publishProfile(row.id)
    if (outcome.published) {
      published += 1
      out(`  published  ${row.display_name ?? row.id}  ${outcome.eventId ?? ''}`)
    } else {
      out(`  FAILED     ${row.display_name ?? row.id}  ${outcome.reason ?? 'unknown'}`)
    }
  }

  out()
  out(`${published}/${rows.length} republished.`)
  if (published !== rows.length) {
    out('Re-run after fixing the failures — republishing an unchanged profile is a no-op.')
    process.exitCode = 1
  }
}

try {
  await main()
} catch (error) {
  process.stderr.write(`${(error as Error).message}\n`)
  process.exitCode = 1
} finally {
  await closePool()
}
