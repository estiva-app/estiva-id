/**
 * The key that acts on the relay as an operator (PEEK-94).
 *
 * Buzz restricts both halves of membership to relay `owner`/`admin`: reading
 * the roster, and the kind:9030/9031 commands that change it. So none of it can
 * be signed as the person being acted on — who, for every interesting case, is
 * exactly the one *not* in the roster. It is signed as an operator.
 *
 * ## Why a role identity rather than a key in the environment
 *
 * A raw secret in `.env` would be the only key in this service not sealed in an
 * envelope, and the only one a database dump plus an environment listing would
 * yield together. A **role identity** (PEEK-34) is already the modelled answer
 * for "the org is the principal": custodied outright, no passkey, nobody to
 * sign in as it. This just points at one.
 *
 * ## The bootstrap is manual, and cannot not be
 *
 * The first admission cannot be granted by the thing requesting it. Somebody
 * with shell access runs `buzz-admin add-member --role admin` once for the
 * operator's pubkey — the same shape as minting the first invite, and for the
 * same reason.
 */
import { config } from '../config.js'
import { withUserSecretKey } from './keys.js'
import { findUserById } from './users.js'

export class NoOperatorIdentity extends Error {
  constructor(readonly reason: 'not-configured' | 'no-such-identity' | 'not-active') {
    super(
      {
        'not-configured': 'RELAY_OPERATOR_USER_ID is not set',
        'no-such-identity': 'RELAY_OPERATOR_USER_ID names an identity that does not exist',
        'not-active': 'the relay operator identity is not active',
      }[reason],
    )
    this.name = 'NoOperatorIdentity'
  }
}

/** Whether operator actions are possible at all, without attempting one. */
export function operatorConfigured(): boolean {
  return config().RELAY_OPERATOR_USER_ID !== ''
}

/**
 * Whether this identity is the one the workspace acts through (PEEK-102).
 *
 * Worth a named predicate rather than an inline config comparison, because
 * three separate places have to agree about it: the guard that refuses to
 * offboard it, the reinstatement that re-admits it, and the row that marks it.
 * A workspace-wide capability disabled by a mis-click is exactly the failure
 * that came from nobody asking this question.
 */
export function isOperatorIdentity(userId: string): boolean {
  const operator = config().RELAY_OPERATOR_USER_ID
  return operator !== '' && operator === userId
}

/**
 * Run something with the operator's secret key in scope.
 *
 * Same shape as {@link withUserSecretKey} — the key is used and dropped, never
 * returned. Callers get a signature, not a secret.
 */
export async function withOperatorSecretKey<T>(
  use: (secretKey: Buffer, pubkey: string) => T | Promise<T>,
): Promise<T> {
  const userId = config().RELAY_OPERATOR_USER_ID
  if (!userId) throw new NoOperatorIdentity('not-configured')

  const operator = await findUserById(userId)
  if (!operator) throw new NoOperatorIdentity('no-such-identity')
  // An offboarded operator must stop acting, exactly like any other identity —
  // otherwise disabling it in the console would leave it quietly driving the
  // relay's membership table.
  if (operator.status !== 'active') throw new NoOperatorIdentity('not-active')

  return withUserSecretKey(userId, use)
}
