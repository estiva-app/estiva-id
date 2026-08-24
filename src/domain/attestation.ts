/**
 * Who steers a bot, said cryptographically rather than in a display name.
 *
 * Production holds a role identity called "Claude (steered by Miky)". That name
 * asserts an ownership nothing verifies: `kind:0` is self-published, so any key
 * the relay has admitted can claim to be steered by anybody. In a ticket feed an
 * unattributable actor is untidy; in a conversation it is misleading, which is
 * why `estiva-agent/CLAUDE.md` calls the display name "a placeholder and a weak
 * one".
 *
 * Migration 008 already records the real answer in `users.owner_user_id`, and
 * Estiva ID custodies both keys — the owner's and the bot's. That makes it the
 * only party in the system that can *prove* the relationship to a third party,
 * which is what {@link ownerAttestation} produces: a NIP-OA tag signed by the
 * owner's key naming the bot's key. Buzz verifies it with no trust in us at all
 * and records the result in `users.agent_owner_pubkey`.
 *
 * ## The signature is over a bare digest, not an event
 *
 * `/sign` cannot produce this and should not learn how. That endpoint's contract
 * is "a Nostr event, attributed to the caller, within the caller's kind
 * ceiling", and a NIP-OA attestation is none of those things: it is a raw
 * SHA-256 signed directly, it is attributed to the *owner* rather than the
 * caller, and the caller is precisely the party who must not be able to ask for
 * it. `domain/profile.ts` makes the same argument about `kind:0` and reaches
 * `withUserSecretKey` the same way, for the same reason.
 *
 * ## Why this is minted at token time
 *
 * The attestation is not a secret and not a credential — it proves a
 * relationship, grants nothing on its own, and is worthless without the agent's
 * own key to go with it. Handing it over with the token means the agent never
 * has to ask a second question, and PEEK-172 already established `/token` as the
 * place a caller learns facts about itself rather than discovering them by being
 * refused.
 */
import { queryOne } from '../db/pool.js'
import { logger } from '../logger.js'
import { type AuthTag, computeAuthTag } from '../nostr/nip-oa.js'
import { withUserSecretKey } from './keys.js'

/**
 * Mint the NIP-OA attestation for a role identity, if it has an owner.
 *
 * Returns `undefined` — never throws — when there is nothing to attest:
 *
 *   * the identity is the workspace's rather than a person's (`owner_user_id`
 *     is null, which is the correct and permanent state for `Relay Operator`);
 *   * the owner has no active key, so there is nothing to sign with;
 *   * the bot has no active key, so there is nothing to name.
 *
 * **A failure here must not fail token issuance.** The attestation is an
 * enhancement to a token that worked without it for a year; a bot that cannot
 * be attributed is a worse bot, while a bot that cannot get a token is a broken
 * one. The same trade `publishProfile` makes when the relay is down.
 */
export async function ownerAttestation(roleUserId: string): Promise<AuthTag | undefined> {
  try {
    /*
      One query for both halves, and both statuses checked.

      The owner's `status` matters as much as the key's: offboarding sets
      `users.status` and leaves `user_keys` alone (see `findSignerByPubkey`),
      so joining on the key alone would keep attesting a departed person's
      ownership of a live bot. `on delete restrict` in migration 008 stops the
      owner row vanishing, not the person leaving.
    */
    const row = await queryOne<{
      owner_user_id: string
      owner_status: string
      agent_pubkey: string
    }>(
      `select bot.owner_user_id,
              owner.status as owner_status,
              bot_key.pubkey as agent_pubkey
         from users bot
         join users owner on owner.id = bot.owner_user_id
         join user_keys bot_key on bot_key.user_id = bot.id and bot_key.status = 'active'
        where bot.id = $1`,
      [roleUserId],
    )

    if (!row) return undefined
    if (row.owner_status !== 'active') {
      logger.info(
        { roleUserId, ownerStatus: row.owner_status },
        'owner is not active; no NIP-OA attestation minted',
      )
      return undefined
    }

    return await withUserSecretKey(row.owner_user_id, (ownerSecretKey) =>
      computeAuthTag(ownerSecretKey, row.agent_pubkey),
    )
  } catch (error) {
    // `withUserSecretKey` throws when the owner has no active key. That is a
    // real state — a person mid-recovery — and not a reason to refuse the bot
    // a token, so it is logged and swallowed like every other absence above.
    logger.warn({ err: error, roleUserId }, 'could not mint NIP-OA owner attestation')
    return undefined
  }
}
