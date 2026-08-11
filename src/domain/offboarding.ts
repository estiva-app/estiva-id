/**
 * Offboarding, in one action (PEEK-66).
 *
 * A leaver keeps their keypair. That is inherent — no database write takes a
 * private key back — so offboarding is never "delete the identity". It is
 * withdrawing three things the org *does* control, and a fourth it does not:
 *
 * | Step | Owner | Effect |
 * | --- | --- | --- |
 * | Revoke every passkey | here | they cannot authenticate again |
 * | Disable the account, kill sessions | here | `/token` and `/sign` refuse them |
 * | Republish `kind:0` without `nip05` | here | the handle stops resolving |
 * | **Revoke community admission** | **Buzz** | the relay stops accepting them |
 *
 * ## Why this is one call and not a checklist
 *
 * Because a partially-offboarded leaver is a security problem, and a manual
 * sequence guarantees one eventually. The failure is silent from both ends: this
 * service shows somebody `offboarded` while the relay still takes their events.
 *
 * ## Order, and why it is this way round
 *
 * The local revocations run **first**, because they cannot fail — they are
 * writes to our own database. Republishing the profile is a network call to the
 * relay and can fail, and a relay outage must not be able to leave somebody's
 * login working. Doing it the other way round means the one step that can fail
 * gates the three that cannot.
 *
 * The key is deliberately **left active**. Revoking it would make everything the
 * person ever signed unattributable, which is the opposite of what offboarding
 * should mean — the org keeps the record. It also does not need revoking:
 * `/sign` refuses on `users.status`, not on the key (PEEK-88).
 *
 * ## The fourth step, and why this returns something awkward
 *
 * **Estiva ID cannot revoke relay admission.** Buzz owns it (PEEK-36) and
 * exposes no HTTP surface for it at all — `buzz-admin` is a CLI against Buzz's
 * own Postgres, and reaching into another service's database is the coupling
 * this suite exists to refuse.
 *
 * So this does three of four and **says so**, rather than returning a cheerful
 * success. The result carries the exact command an operator still has to run.
 * A green tick here, with the relay still admitting them, would be worse than
 * no button at all: it would convert a known manual step into an unknown one.
 */
import { recordAudit } from './audit.js'
import { revokeAllCredentials } from './credentials.js'
import { getActivePubkey } from './keys.js'
import { getProfile, publishProfile, saveProfile } from './profile.js'
import { removeMemberCommand, revokeMember } from './relay-membership.js'
import { findUserById, setUserStatus } from './users.js'

export interface OffboardResult {
  userId: string
  pubkey: string | null
  /** How many passkeys were still live. */
  passkeysRevoked: number
  sessionsRevoked: number
  /** The handle that was withdrawn, if they had one. */
  handleRevoked: string | null
  /**
   * Whether the `kind:0` carrying the withdrawal reached the relay. **False
   * means the handle still resolves** for anyone who reads the old event.
   */
  attestationPublished: boolean
  publishError?: string | undefined
  /**
   * The fourth step, which used to be somebody else's problem (PEEK-94).
   *
   * Buzz still *owns* admission — this publishes a signed kind:9031 through the
   * bridge and the relay decides, exactly as PEEK-36 intended. What changed is
   * that the decision can now be asked for, rather than printed as a command
   * and hoped for.
   *
   * `revoked: false` is still reachable — no operator identity configured, the
   * relay unreachable, the operator not an admin — and when it is, the command
   * comes back so the step is still completable by hand. A step that silently
   * did not happen is the failure this whole ticket exists to prevent.
   */
  relayAdmission: {
    revoked: boolean
    reason?: string
    /** Present whenever `revoked` is false: run this on the box. */
    command?: string
  }
}

export class AlreadyOffboarded extends Error {
  constructor() {
    super('That identity is already offboarded')
    this.name = 'AlreadyOffboarded'
  }
}

export class NoSuchPerson extends Error {
  constructor() {
    super('No such person')
    this.name = 'NoSuchPerson'
  }
}

/**
 * The command an operator has to run **when this service could not**.
 *
 * Built with the pubkey filled in, because the failure this whole ticket exists
 * to prevent is somebody not completing a step — and "look up their pubkey,
 * then construct a command" is two more chances to stop.
 */
export function revokeAdmissionCommand(pubkey: string | null): string {
  return removeMemberCommand(pubkey)
}

export async function offboardPerson(
  userId: string,
  by: { actorUserId?: string | undefined; requestId?: string | undefined } = {},
): Promise<OffboardResult> {
  const user = await findUserById(userId)
  if (!user) throw new NoSuchPerson()
  if (user.status === 'offboarded') throw new AlreadyOffboarded()

  const pubkey = (await getActivePubkey(userId)) ?? null
  // Read before withdrawing it, so the record can say what was taken away.
  const handle = (await getProfile(userId))?.handle ?? null

  // --- The part that cannot fail ------------------------------------------
  const passkeysRevoked = await revokeAllCredentials(userId)
  const { sessionsRevoked } = await setUserStatus(userId, 'offboarded', by)

  // --- The part that can ----------------------------------------------------
  // Clearing the handle is a local write; the publish that makes it *mean*
  // anything is not. An explicit null clears — an absent key would leave it.
  let attestationPublished = false
  let publishError: string | undefined
  if (handle) {
    await saveProfile(userId, { handle: null })
    const outcome = await publishProfile(userId, by)
    attestationPublished = outcome.published
    publishError = outcome.published ? undefined : outcome.reason
  } else {
    // Nothing to withdraw, so nothing to publish and nothing left resolving.
    attestationPublished = true
  }

  /*
    The fourth step (PEEK-94). Last, because it is the one that can fail for
    reasons outside this service — and the three above must not be held hostage
    to the relay being reachable. A leaver with their passkeys revoked and their
    handle withdrawn is already mostly out; this closes the half that was
    silent.

    A pubkey nobody ever admitted is `alreadyInState`, not a failure: the end
    state is what was asked for.
  */
  const admissionResult = pubkey
    ? await revokeMember(pubkey)
    : { ok: false, reason: 'no active key for this identity' }

  await recordAudit({
    actorType: by.actorUserId ? 'user' : 'system',
    actorUserId: by.actorUserId,
    action: 'user.offboard',
    // `refused` would be wrong — nothing refused this. The relay step being
    // outstanding is the normal, designed outcome, so it stays a success with
    // the gap recorded in the detail.
    outcome: 'success',
    subjectPubkey: pubkey ?? undefined,
    detail: {
      subjectUserId: userId,
      passkeysRevoked,
      sessionsRevoked,
      handleRevoked: handle,
      attestationPublished,
      ...(publishError ? { publishError } : {}),
      relayAdmissionRevoked: admissionResult.ok,
      ...(admissionResult.ok ? {} : { relayAdmissionError: admissionResult.reason }),
    },
    requestId: by.requestId,
  })

  return {
    userId,
    pubkey,
    passkeysRevoked,
    sessionsRevoked,
    handleRevoked: handle,
    attestationPublished,
    publishError,
    relayAdmission: admissionResult.ok
      ? { revoked: true }
      : {
          revoked: false,
          reason: admissionResult.reason ?? 'unknown',
          // Still handed back, so a failure here is completable by hand rather
          // than merely reported.
          command: revokeAdmissionCommand(pubkey),
        },
  }
}
