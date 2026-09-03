/**
 * Republish every kind:0 whose picture is still the relay's URL (SHA-22).
 *
 *   pnpm avatars:republish            # what would change
 *   APPLY=1 pnpm avatars:republish    # publish
 *
 * ## Why a one-off step is unavoidable
 *
 * `picture` is published, and a published event is a copy. The route and the
 * mapping fix what this service *serves* and what it publishes *next*, but the
 * `kind:0` already on the relay still names `https://<relay>/media/<hash>.jpg`
 * — and that is the string Ship and Peek read. Until each of those events is
 * replaced, every app keeps rendering a URL that answers `401`, with the new
 * code deployed and working. That is the shape of failure this repo keeps
 * relearning: built is not deployed, and deployed is not in effect.
 *
 * kind:0 is replaceable, so this is a rewrite rather than an accumulation —
 * running it twice publishes the same content twice and changes nothing.
 *
 * ## Why it does not touch the database
 *
 * `users.picture` deliberately keeps the relay's content-addressed URL as the
 * record; `avatarDisplayUrl` maps it on the way out. So there is nothing to
 * migrate — only events to re-emit. A row is left exactly as it was, which is
 * also what makes this safe to run again after a rollback.
 *
 * ## Why it lives in `src/`
 *
 * Same reason as `create-invite.ts`: `scripts/` does not ship. On the box:
 *
 *   docker compose run --rm -T -e APPLY=1 \
 *     estiva-id node dist/admin/republish-avatars.js
 */
import { config } from '../config.js'
import { closePool, query } from '../db/pool.js'
import { avatarDisplayUrl } from '../domain/avatar-url.js'
import { publishProfile } from '../domain/profile.js'

const APPLY = /^(1|true|yes|on)$/i.test(process.env.APPLY ?? '')

const out = (line = '') => process.stdout.write(`${line}\n`)

interface Row {
  id: string
  email: string | null
  picture: string
}

async function main(): Promise<void> {
  const relay = config().RELAY_BRIDGE_URL
  if (!relay) throw new Error('RELAY_BRIDGE_URL is not set — there is nothing to publish to')

  /*
    Active identities only. An offboarded person's kind:0 was deliberately
    republished without their attestation by `offboardPerson`, and re-signing
    it here would be a second opinion about a decision that has already been
    made and audited.
  */
  const { rows } = await query<Row>(
    `select id, email, picture
       from users
      where status = 'active'
        and picture is not null
        and picture like $1
      order by email nulls last`,
    [`${relay}/media/%`],
  )

  if (rows.length === 0) {
    out('Nothing to do — no active identity still publishes a relay media URL.')
    return
  }

  out(`${rows.length} identit${rows.length === 1 ? 'y' : 'ies'} to republish:`)
  out()
  for (const row of rows) {
    out(`  ${row.email ?? row.id}`)
    out(`    was  ${row.picture}`)
    out(`    now  ${avatarDisplayUrl(row.picture)}`)
  }
  out()

  if (!APPLY) {
    out('Dry run. Set APPLY=1 to publish.')
    return
  }

  let published = 0
  for (const row of rows) {
    // Reported per identity rather than aborting the run: one key that cannot
    // be unsealed, or one pubkey the relay has not admitted, must not leave
    // the rest of the workspace unfixed.
    const outcome = await publishProfile(row.id)
    if (outcome.published) {
      published += 1
      out(`  published  ${row.email ?? row.id}  ${outcome.eventId ?? ''}`)
    } else {
      out(`  FAILED     ${row.email ?? row.id}  ${outcome.reason ?? 'unknown'}`)
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
