/**
 * Users.
 *
 * Email is a *private* directory attribute: it is stored here, it is never
 * published to a relay, and it never appears in a kind:0 event. That split is
 * the point of having a private directory alongside the public profile.
 */
import { queryOne, withTransaction } from '../db/pool.js'
import { mintKeyForUser } from './keys.js'

export interface User {
  id: string
  email: string | null
  display_name: string | null
  status: 'active' | 'suspended' | 'offboarded'
}

export interface UserWithPubkey extends User {
  pubkey: string
}

export async function findUserByEmail(email: string): Promise<User | undefined> {
  return queryOne<User>(
    'select id, email, display_name, status from users where lower(email) = lower($1)',
    [email],
  )
}

export async function findUserById(id: string): Promise<User | undefined> {
  return queryOne<User>('select id, email, display_name, status from users where id = $1', [id])
}

/**
 * Create a user and mint their key in one transaction.
 *
 * A user without a key would be an account that cannot act, and a key without a
 * user would be an orphaned secret. Neither is a state worth being able to
 * represent, so both happen or neither does.
 */
export async function createUserWithKey(input: {
  email: string
  displayName?: string | undefined
}): Promise<UserWithPubkey> {
  return withTransaction(async (client) => {
    const inserted = await client.query<User>(
      `insert into users (email, display_name) values ($1, $2)
       returning id, email, display_name, status`,
      [input.email, input.displayName ?? null],
    )
    const user = inserted.rows[0]
    if (!user) throw new Error('user insert returned no row')

    const pubkey = await mintKeyForUser(client, user.id)
    return { ...user, pubkey }
  })
}
