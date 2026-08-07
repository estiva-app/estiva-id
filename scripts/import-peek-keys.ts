/**
 * PEEK-37 — move Estiva Peek's custodied keys into Estiva ID, under the same
 * pubkeys, so nothing already published becomes unverifiable.
 *
 *   npx convex run dev/migrationAudit:exportCustodiedKeys --output-file keys.json
 *   PEEK_KEY_SECRET=$(npx convex env get NOSTR_KEY_ENCRYPTION_SECRET) \
 *     npx tsx scripts/import-peek-keys.ts keys.json          # dry run
 *   PEEK_KEY_SECRET=… npx tsx scripts/import-peek-keys.ts keys.json --commit
 *
 * ## The failure this exists to avoid
 *
 * A key that arrives under a *different* pubkey is worse than one that fails to
 * arrive: the account still works, still signs, and everything the person
 * published before the migration silently detaches from them. Nobody notices
 * until someone checks a signature months later.
 *
 * So every key is decrypted, its pubkey **derived from the secret**, and
 * compared against what Peek claimed. A mismatch aborts that record rather than
 * writing something plausible. That check also catches a wrong passphrase, a
 * corrupted blob, and a row whose pubkey and secret were never a pair.
 *
 * ## Handling of secrets
 *
 * Blobs arrive still encrypted under Peek's key. They are decrypted in memory,
 * re-sealed into this service's envelope, and zeroed. The plaintext secret never
 * reaches a file, a log line, or stdout — including in `--dry-run`, which
 * decrypts and verifies but writes nothing.
 *
 * Idempotent: a pubkey already present here is skipped, so a partial run can be
 * repeated safely. Reads only from Peek — nothing there is modified, so the
 * whole operation is reversible by deleting what it wrote here.
 */
import { readFileSync } from 'node:fs'
import { sealEnvelope } from '../src/crypto/envelope.js'
import { closePool, queryOne, withTransaction } from '../src/db/pool.js'
import { currentKek, currentKid } from '../src/domain/kek.js'
import { withUserSecretKey } from '../src/domain/keys.js'
import { checkPair, decryptPeekSecret } from '../src/migration/peek.js'
import { signEvent, verifyEvent } from '../src/nostr/keys.js'

interface PeekRecord {
  name: string
  email: string | null
  pubkey: string
  encryptedSecret: string
}

async function main(): Promise<void> {
  const file = process.argv[2]
  const commit = process.argv.includes('--commit')
  const passphrase = process.env.PEEK_KEY_SECRET

  if (!file) throw new Error('usage: import-peek-keys.ts <export.json> [--commit]')
  if (!passphrase)
    throw new Error('PEEK_KEY_SECRET is required (Peek’s NOSTR_KEY_ENCRYPTION_SECRET)')

  const records = JSON.parse(readFileSync(file, 'utf8')) as PeekRecord[]
  const out = (line: string) => process.stdout.write(`${line}\n`)

  out(commit ? 'COMMIT — writing keys' : 'DRY RUN — verifying only, nothing will be written')
  out(`${records.length} record(s) from Estiva Peek\n`)

  let imported = 0
  let skipped = 0
  let failed = 0

  for (const record of records) {
    const label = `${record.name} (${record.pubkey.slice(0, 12)}…)`

    const existing = await queryOne<{ pubkey: string }>(
      'select pubkey from user_keys where pubkey = $1',
      [record.pubkey],
    )
    if (existing) {
      out(`  skip     ${label} — already here`)
      skipped += 1
      continue
    }

    let secret: Buffer
    try {
      secret = decryptPeekSecret(record.encryptedSecret, passphrase)
    } catch (error) {
      out(`  FAIL     ${label} — decrypt: ${(error as Error).message}`)
      failed += 1
      continue
    }

    try {
      // The check this whole script exists for — see src/migration/peek.ts.
      const pair = checkPair(secret, record.pubkey)
      if (!pair.ok) {
        out(`  FAIL     ${label} — derived ${pair.derived.slice(0, 12)}…, refusing to write`)
        failed += 1
        continue
      }

      if (!commit) {
        out(`  ok       ${label} — decrypts and matches`)
        imported += 1
        continue
      }

      const userId = await withTransaction(async (client) => {
        const inserted = await client.query<{ id: string }>(
          `insert into users (email, display_name) values ($1, $2) returning id`,
          [record.email, record.name],
        )
        const id = inserted.rows[0]?.id
        if (!id) throw new Error('user insert returned no row')

        const envelope = sealEnvelope({
          secret,
          aad: { userId: id, pubkey: record.pubkey },
          kek: currentKek(),
          kid: currentKid(),
        })
        await client.query(
          'insert into user_keys (user_id, pubkey, envelope) values ($1, $2, $3)',
          [id, record.pubkey, JSON.stringify(envelope)],
        )
        return id
      })

      // Read it back the way the service will, and sign — the ticket's own bar.
      const signed = await withUserSecretKey(userId, (sk, pubkey) =>
        signEvent(
          { pubkey, created_at: 1_785_000_000, kind: 9, tags: [], content: 'migration check' },
          sk,
        ),
      )
      if (!verifyEvent(signed) || signed.pubkey !== record.pubkey) {
        throw new Error('post-import signature did not verify under the original pubkey')
      }

      out(`  imported ${label} — signs correctly`)
      imported += 1
    } finally {
      secret.fill(0)
    }
  }

  out(`\n${imported} ${commit ? 'imported' : 'verified'}, ${skipped} skipped, ${failed} failed`)
  if (failed > 0) process.exitCode = 1
}

try {
  await main()
} finally {
  await closePool()
}
