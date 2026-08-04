/**
 * What `/sign` will and will not sign, per app (PEEK-71).
 *
 * As originally specced, `/sign` is a rubber stamp: hand it anything, get it
 * back signed as the user. A stolen browser token could then rewrite that
 * person's profile, delete their posts, or mint a NIP-98 credential to read the
 * relay directly, bypassing the apps entirely.
 *
 * Two rules matter more than the exact kind lists:
 *
 *   1. **No app may sign kind:0.** The identity service owns profiles; an app
 *      that can publish one can undo that ownership. This is checked before the
 *      per-app allowlist, so it cannot be granted by adding 0 to a row.
 *   2. **NIP-98 (27235) is constrained by URL**, to the relay bridge only.
 *      Otherwise the endpoint mints HTTP credentials for arbitrary destinations.
 *
 * Everything here is a pure function over a policy and an event, so the rules
 * are testable without a database or a running server.
 */
import type { UnsignedEvent } from '../nostr/event.js'
import { tagValue } from '../nostr/event.js'

/** Profiles belong to the identity service (PEEK-31). Never signable via /sign. */
export const KIND_PROFILE = 0
/** NIP-98 HTTP auth. Signable only for allowlisted URLs. */
export const KIND_HTTP_AUTH = 27235

export interface AppPolicy {
  clientId: string
  name: string
  allowedKinds: number[]
  nip98UrlPrefixes: string[]
  status: 'active' | 'disabled'
}

export type PolicyRefusalReason =
  | 'app_disabled'
  | 'kind_profile_forbidden'
  | 'kind_not_allowed'
  | 'nip98_missing_url'
  | 'nip98_url_not_allowed'

export type PolicyDecision =
  | { allowed: true }
  | { allowed: false; reason: PolicyRefusalReason; message: string }

const refuse = (reason: PolicyRefusalReason, message: string): PolicyDecision => ({
  allowed: false,
  reason,
  message,
})

/**
 * Decide whether `app` may have `event` signed.
 *
 * `deploymentNip98Prefixes` is the outer bound — what this deployment will ever
 * mint NIP-98 for. An app's own list narrows within it and can never widen it.
 * Both default to empty, so 27235 is refused until somebody decides where the
 * relay bridge lives (PEEK-33). Fail-closed matches Buzz's own posture on
 * `pubkey_allowlist`.
 */
export function evaluateSignPolicy(
  event: UnsignedEvent,
  app: AppPolicy,
  deploymentNip98Prefixes: readonly string[],
): PolicyDecision {
  if (app.status !== 'active') {
    return refuse('app_disabled', `App ${app.clientId} is disabled`)
  }

  // Checked first and unconditionally: this must not be grantable by editing a
  // row, because the row is the thing an attacker with database access edits.
  if (event.kind === KIND_PROFILE) {
    return refuse(
      'kind_profile_forbidden',
      'kind:0 is published only by the identity service, never through /sign',
    )
  }

  if (!app.allowedKinds.includes(event.kind)) {
    return refuse('kind_not_allowed', `App ${app.clientId} may not sign kind ${event.kind}`)
  }

  if (event.kind === KIND_HTTP_AUTH) {
    const url = tagValue(event, 'u')
    if (!url) {
      return refuse('nip98_missing_url', 'A kind 27235 event must carry a "u" tag')
    }

    const allowedByDeployment = deploymentNip98Prefixes.some((prefix) => url.startsWith(prefix))
    const allowedByApp = app.nip98UrlPrefixes.some((prefix) => url.startsWith(prefix))

    if (!allowedByDeployment || !allowedByApp) {
      return refuse(
        'nip98_url_not_allowed',
        'That URL is not an allowed NIP-98 destination for this app',
      )
    }
  }

  return { allowed: true }
}
