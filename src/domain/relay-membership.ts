/**
 * Driving relay membership, at last (PEEK-94).
 *
 * Offboarding did three of its four steps and printed the fourth for a human to
 * run. Until somebody ran it, **a leaver kept reading and writing on the relay
 * with the key they still held** — the exact failure PEEK-66 exists to prevent,
 * reduced from silent to merely manual, which is an improvement and not a fix.
 *
 * ## Why this needs no new endpoint on Buzz
 *
 * The original ticket asked for `POST`/`DELETE /api/members`. They are not
 * needed: the relay has accepted membership changes as **signed kind:9030 and
 * 9031 events** all along, through the same `POST /events` bridge this service
 * already publishes `kind:0` to. `handlers/relay_admin.rs` enforces the
 * authorization — sender must be `admin` or `owner`, adds are idempotent,
 * removal by an admin uses an atomic conditional delete to close the race where
 * a target is promoted mid-flight — and it republishes the NIP-43 membership
 * list afterwards so live clients notice.
 *
 * Adding a REST path beside that would mean two privileged writes over one
 * table, each carrying its own copy of those rules, drifting apart quietly.
 * What Buzz genuinely lacked was a way to *read*, which is `api/members.rs`.
 *
 * ## Every call here is signed by the operator, not the subject
 *
 * The relay requires the sender to be an admin or owner. A leaver is neither,
 * and neither is somebody who has never been admitted — so signing as the
 * subject would fail in exactly the cases that matter. See `operator-key.ts`.
 */

import { signEvent } from '../nostr/keys.js'
import { publishEvent } from '../nostr/relay.js'
import { NoOperatorIdentity, withOperatorSecretKey } from './operator-key.js'

/** NIP-43 relay membership admin commands, as Buzz numbers them. */
export const KIND_ADD_MEMBER = 9030
export const KIND_REMOVE_MEMBER = 9031

export interface MembershipChange {
  ok: boolean
  /** What to tell an operator when this did not work. */
  reason?: string
  /** True when the relay already agreed — an add of a member, or a remove of a non-member. */
  alreadyInState?: boolean
}

/**
 * The command a human would otherwise run, kept for when this cannot.
 *
 * Still built with the pubkey filled in: the failure being guarded against is
 * somebody not completing a step, and "look up their pubkey, then construct a
 * command" is two more chances to stop.
 */
export function addMemberCommand(pubkey: string | null): string {
  return `docker exec buzz-prod-relay-1 buzz-admin add-member --pubkey ${pubkey ?? '<pubkey>'}`
}

export function removeMemberCommand(pubkey: string | null): string {
  return `docker exec buzz-prod-relay-1 buzz-admin remove-member --pubkey ${pubkey ?? '<pubkey>'}`
}

async function publishMembershipCommand(
  kind: number,
  targetPubkey: string,
): Promise<MembershipChange> {
  try {
    return await withOperatorSecretKey(async (secretKey, operatorPubkey) => {
      const event = signEvent(
        {
          pubkey: operatorPubkey,
          created_at: Math.floor(Date.now() / 1000),
          kind,
          tags: [['p', targetPubkey]],
          content: '',
        },
        secretKey,
      )

      const result = await publishEvent(event, secretKey)
      if (result.ok) return { ok: true }

      // The relay treats a no-op as a refusal in some paths and a duplicate in
      // others; neither is a failure to act on, because the end state is right.
      if (result.duplicate) return { ok: true, alreadyInState: true }
      return { ok: false, reason: result.reason ?? `relay answered ${result.httpStatus}` }
    })
  } catch (error) {
    if (error instanceof NoOperatorIdentity) return { ok: false, reason: error.message }
    return {
      ok: false,
      reason: error instanceof Error ? error.message : 'could not reach the relay',
    }
  }
}

/** Admit a pubkey to the workspace's relay. */
export function admitMember(pubkey: string): Promise<MembershipChange> {
  return publishMembershipCommand(KIND_ADD_MEMBER, pubkey)
}

/**
 * Withdraw a pubkey's admission — offboarding's fourth step.
 *
 * The relay refuses an admin removing *themselves*, which is why the operator
 * identity must never be the subject of an offboarding. It is a role identity
 * with no way to sign in, so it should never be one.
 */
export function revokeMember(pubkey: string): Promise<MembershipChange> {
  return publishMembershipCommand(KIND_REMOVE_MEMBER, pubkey)
}
