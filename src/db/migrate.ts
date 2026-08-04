/**
 * Migration runner.
 *
 * Plain `.sql` files applied in filename order, each in its own transaction,
 * recorded in `schema_migrations`. No ORM and no DSL: someone auditing what
 * happens to key material should be able to read the schema as SQL.
 */
import { createHash } from 'node:crypto'
import { readFile, readdir } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { closePool, getPool, query } from './pool.js'

const MIGRATIONS_DIR = join(dirname(fileURLToPath(import.meta.url)), '../../migrations')

interface AppliedRow {
  name: string
  checksum: string
}

async function ensureMigrationsTable(): Promise<void> {
  await query(`
    create table if not exists schema_migrations (
      name       text primary key,
      checksum   text not null,
      applied_at timestamptz not null default now()
    )
  `)
}

function checksum(sql: string): string {
  return createHash('sha256').update(sql).digest('hex')
}

export async function migrate(log: (message: string) => void = () => {}): Promise<number> {
  await ensureMigrationsTable()

  const applied = new Map<string, string>()
  const rows = await query<AppliedRow>('select name, checksum from schema_migrations')
  for (const row of rows.rows) applied.set(row.name, row.checksum)

  const files = (await readdir(MIGRATIONS_DIR)).filter((f) => f.endsWith('.sql')).sort()

  let count = 0
  for (const name of files) {
    const sql = await readFile(join(MIGRATIONS_DIR, name), 'utf8')
    const digest = checksum(sql)
    const previous = applied.get(name)

    if (previous !== undefined) {
      // An edited migration means the database and the repo disagree about what
      // the schema is. Refusing is the only safe answer — silently skipping
      // leaves a deployment whose schema nobody can reproduce.
      if (previous !== digest) {
        throw new Error(
          `Migration ${name} has changed since it was applied (recorded ${previous.slice(0, 12)}, file ${digest.slice(0, 12)}). Add a new migration instead of editing an applied one.`,
        )
      }
      continue
    }

    const client = await getPool().connect()
    try {
      await client.query('BEGIN')
      await client.query(sql)
      await client.query('insert into schema_migrations (name, checksum) values ($1, $2)', [
        name,
        digest,
      ])
      await client.query('COMMIT')
      log(`applied ${name}`)
      count += 1
    } catch (error) {
      await client.query('ROLLBACK')
      throw new Error(`Migration ${name} failed: ${(error as Error).message}`, { cause: error })
    } finally {
      client.release()
    }
  }

  return count
}

const isEntrypoint = process.argv[1] === fileURLToPath(import.meta.url)

if (isEntrypoint) {
  try {
    const applied = await migrate((message) => process.stdout.write(`${message}\n`))
    process.stdout.write(
      applied === 0 ? 'schema up to date\n' : `${applied} migration(s) applied\n`,
    )
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n`)
    process.exitCode = 1
  } finally {
    await closePool()
  }
}
