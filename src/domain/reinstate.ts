/**
 * Putting somebody back (PEEK-102).
 *
 * PEEK-66 built offboarding and deliberately left reinstatement out — removing
 * somebody is the operation where a half-finished checklist is dangerous, and
 * the reverse is not, so it was not worth the surface at the time. What that
 * missed is that offboarding is *reachable by mistake*, and the only way back
 * was:
 *
 * ```sql
 * update users set status='active' where id='…';
 * ```
 *
 * An ordinary mis-click should not require a database edit. It did, once, on
 * production, against the relay operator — which is the incident this module and
 * {@link OperatorIdentity} come out of.
 *
 * ## Why its own action, and not a relaxed recovery
 *
 * `createRecovery` refuses a non-active identity, and that guard is **correct**:
 * recovery hands whoever opens the link a working passkey, so allowing it
 * against an offboarded account would make recovery a way back in around
 * offboarding. Reinstating is a different decision, made by an admin about an
 * account rather than by anyone holding a link, so it gets its own audited call
 * rather than a hole in that one.
 *
 * ## What this restores, and what it deliberately does not
 *
 * | Offboarding took | Given back here |
 * | --- | --- |
 * | Account status, sessions | **Yes** — status returns to `active` |
 * | Relay admission | **Yes** — re-admitted, or it is not really reinstated |
 * | Every passkey | **No** |
 * | The `nip05` handle | **No** |
 *
 * **Passkeys stay revoked on purpose.** Offboarding revokes them because the
 * devices holding them are leaving with a person; un-revoking would hand access
 * back to whatever prompted the offboarding in the first place. So a reinstated
 * human is active with nothing enrolled — they need a recovery link, and the
 * result says so rather than letting an admin believe the job is finished. A
 * role identity has no passkey to lose and comes back whole, which is what makes
 * this a complete fix for the operator case.
 *
 * **The handle is not reclaimed.** It was withdrawn by publishing a `kind:0`
 * without it, and it may have been taken since. Guessing would either fail
 * noisily or silently reassign somebody else's handle; the person sets it again
 * from their account page, which republishes properly.
 */
import { recordAudit } from './audit.js'
import { getActivePubkey } from './keys.js'
import { addMemberCommand, admitMember } from './relay-membership.js'
import { findUserById, setUserStatus } from './users.js'

export interface ReinstateResult {
  userId: string
  pubkey: string | null
  /**
   * Whether the relay took them back. `false` leaves them active here and
   * unable to read or write there — half-reinstated, which is the mirror of the
   * failure offboarding works so hard to avoid, so it is reported not swallowed.
   */
  relayAdmission: {
    admitted: boolean
    reason?: string
    /** Present whenever `admitted` is false: run this on the box. */
    command?: string
  }
  /**
   * True when this account has no live passkey — so an admin knows the person
   * still cannot sign in, and that a recovery link is the next step.
   *
   * Always true for a reinstated human, since offboarding revoked them all.
   * False for a role identity, which never had one and signs with a client
   * credential that offboarding never touched.
   */
  needsRecovery: boolean
}

export class NotOffboarded extends Error {
  constructor() {
    super('That identity is not offboarded')
    this.name = 'NotOffboarded'
  }
}

export class NoSuchPerson extends Error {
  constructor() {
    super('No such person')
    this.name = 'NoSuchPerson'
  }
}

export async function reinstatePerson(
  userId: string,
  by: { actorUserId?: string | undefined; requestId?: string | undefined } = {},
): Promise<ReinstateResult> {
  const user = await findUserById(userId)
  if (!user) throw new NoSuchPerson()
  // Only from `offboarded`. Reinstating an active account is a no-op dressed as
  // an action, and reinstating a *suspended* one would quietly conflate two
  // different decisions somebody made for different reasons.
  if (user.status !== 'offboarded') throw new NotOffboarded()

  const pubkey = (await getActivePubkey(userId)) ?? null

  // Local first, exactly as offboarding does it, and for the mirrored reason:
  // this write cannot fail, and it must not be held hostage to the relay being
  // reachable. Somebody locked out of their own workspace should not stay
  // locked out because Buzz is down.
  await setUserStatus(userId, 'active', by)

  /*
    Then the relay. This is the step that made the incident unrecoverable rather
    than merely annoying: the operator's status could be flipped back with one
    SQL statement, but its pubkey was gone from `relay_members`, so every roster
    read would still have 403'd. A reinstatement that skipped this would look
    like it worked and leave admission just as broken.

    A pubkey the relay already admits comes back `alreadyInState` — a success,
    because the end state is the one asked for.
  */
  const admission = pubkey
    ? await admitMember(pubkey)
    : { ok: false, reason: 'no active key for this identity' }

  const needsRecovery = user.kind !== 'role'

  await recordAudit({
    actorType: by.actorUserId ? 'user' : 'system',
    actorUserId: by.actorUserId,
    action: 'user.reinstate',
    outcome: 'success',
    subjectPubkey: pubkey ?? undefined,
    detail: {
      subjectUserId: userId,
      relayAdmissionRestored: admission.ok,
      ...(admission.ok ? {} : { relayAdmissionError: admission.reason }),
      needsRecovery,
    },
    requestId: by.requestId,
  })

  return {
    userId,
    pubkey,
    relayAdmission: admission.ok
      ? { admitted: true }
      : {
          admitted: false,
          reason: admission.reason ?? 'unknown',
          command: addMemberCommand(pubkey),
        },
    needsRecovery,
  }
}
