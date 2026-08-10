/**
 * WebAuthn ceremony challenges.
 *
 * Single-use and short-lived. Consumption is a conditional UPDATE rather than a
 * read-then-write, so two concurrent replays of the same challenge cannot both
 * succeed — replaying a challenge is precisely the attack the nonce exists to
 * prevent.
 */
import { query, queryOne } from '../db/pool.js'

const TTL_SECONDS = 300

/**
 * `recovery` is separate from `registration` on purpose (PEEK-67).
 *
 * Both end in a new credential, but only the recovery route also retires the
 * old passkeys and burns the recovery link. Sharing a ceremony would let a
 * recovery challenge be redeemed at `/auth/register/verify`, which does neither
 * — leaving a live link and a lost device that still works. Separating them
 * makes that combination unrepresentable rather than merely unlikely.
 */
export type Ceremony = 'registration' | 'authentication' | 'recovery'

export async function storeChallenge(input: {
  challenge: string
  ceremony: Ceremony
  userId?: string | undefined
}): Promise<void> {
  await query(
    `insert into webauthn_challenges (challenge, ceremony, user_id, expires_at)
     values ($1, $2, $3, now() + make_interval(secs => $4))`,
    [input.challenge, input.ceremony, input.userId ?? null, TTL_SECONDS],
  )
}

/**
 * Atomically claim a challenge. Returns the user it was issued for, if any.
 * A second call with the same challenge returns undefined.
 */
export async function consumeChallenge(
  challenge: string,
  ceremony: Ceremony,
): Promise<{ userId: string | null } | undefined> {
  const row = await queryOne<{ user_id: string | null }>(
    `update webauthn_challenges
        set consumed_at = now()
      where challenge = $1
        and ceremony = $2
        and consumed_at is null
        and expires_at > now()
      returning user_id`,
    [challenge, ceremony],
  )
  return row ? { userId: row.user_id } : undefined
}

/** Housekeeping. Expired rows are worthless once consumed or timed out. */
export async function purgeExpiredChallenges(): Promise<number> {
  const result = await query('delete from webauthn_challenges where expires_at < now()')
  return result.rowCount ?? 0
}
