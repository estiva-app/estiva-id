/**
 * Postgres access.
 *
 * Deliberately a thin wrapper over `pg` rather than an ORM: the schema is small,
 * the queries are explicit, and this service has to be readable by someone
 * auditing what happens to key material.
 */
import pg from 'pg'
import { config } from '../config.js'

const { Pool } = pg

let pool: pg.Pool | undefined

export function getPool(): pg.Pool {
  pool ??= new Pool({
    connectionString: config().DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 30_000,
  })
  return pool
}

export async function query<Row extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<pg.QueryResult<Row>> {
  return getPool().query<Row>(text, params as unknown[])
}

/** First row, or undefined. Reads better than `result.rows[0]` at call sites. */
export async function queryOne<Row extends pg.QueryResultRow = pg.QueryResultRow>(
  text: string,
  params: readonly unknown[] = [],
): Promise<Row | undefined> {
  const result = await query<Row>(text, params)
  return result.rows[0]
}

export async function withTransaction<T>(fn: (client: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await getPool().connect()
  try {
    await client.query('BEGIN')
    const result = await fn(client)
    await client.query('COMMIT')
    return result
  } catch (error) {
    await client.query('ROLLBACK')
    throw error
  } finally {
    client.release()
  }
}

export async function closePool(): Promise<void> {
  await pool?.end()
  pool = undefined
}
