/**
 * Relay admission, observed (PEEK-36, PEEK-64).
 *
 * Onboarding is two operations against two systems: create an identity here,
 * and admit the pubkey to the Buzz community. **Buzz owns the second and keeps
 * it** — the relay checks membership at authentication time against a
 * fail-closed allowlist, formally verified as `Inv_AdmissionFence`. Estiva ID
 * observes that state and displays it; it does not drive it.
 *
 * Observing closes the dangerous half of a manual two-step. Half-onboarded —
 * identity exists, never admitted — is annoying, and someone complains on day
 * one. Half-offboarded — removed here, still admitted at the relay — is a
 * security problem, and a *silent* one unless something draws both facts side
 * by side. That is what this port is for.
 *
 * ## Why the answer is always `unknown` today
 *
 * There is no way to ask. The relay's HTTP surface has no membership read
 * endpoint at all: `crates/buzz-relay/src/router.rs` exposes the bridge, media,
 * NIP-05 and a moderation API covering reports and feedback, and nothing else.
 * The only reader is `buzz-admin list-members`, which is a CLI that opens Buzz's
 * Postgres directly (`crates/buzz-admin/src/main.rs`, `connect_db()`).
 *
 * Estiva ID could therefore only answer this by connecting to another service's
 * database. That is precisely the coupling this suite exists to argue against —
 * apps sharing no code and no database, interoperating through published events
 * (ARCHITECTURE.md §3) — and a shortcut here would be load-bearing in the wrong
 * direction, because it would then be the thing to unpick when workspaces get
 * dedicated deployments.
 *
 * So `unknown` is not a placeholder for an implementation somebody forgot. It is
 * the honest answer until Buzz grows a read endpoint, and it is displayed as
 * such — **never inferred as "probably fine"**, which is the one reading that
 * would make a half-offboarded person look admitted.
 */

/**
 * What is known about a pubkey's standing at the relay.
 *
 * `unknown` is a first-class answer, not an error. A caller that collapses it
 * into either of the other two is asserting something nobody measured.
 */
export type AdmissionStatus = 'admitted' | 'not-admitted' | 'unknown'

export interface AdmissionPort {
  /** One pubkey's standing. */
  getAdmissionStatus(pubkey: string): Promise<AdmissionStatus>

  /**
   * Many at once, for the people list.
   *
   * Separate from the single lookup so that a real implementation can answer a
   * page of people with one request. The default maps over the single form,
   * which costs nothing while every answer is a constant.
   */
  getAdmissionStatuses(pubkeys: readonly string[]): Promise<Map<string, AdmissionStatus>>
}

/**
 * The only implementation there can be right now — see the file docstring.
 *
 * Kept as a named class rather than inlined so that the day Buzz exposes
 * membership, the change is a second implementation and a config switch, not a
 * new seam cut through the callers.
 */
export class UnobservableAdmission implements AdmissionPort {
  async getAdmissionStatus(_pubkey: string): Promise<AdmissionStatus> {
    return 'unknown'
  }

  async getAdmissionStatuses(pubkeys: readonly string[]): Promise<Map<string, AdmissionStatus>> {
    const entries = await Promise.all(
      pubkeys.map(async (pubkey) => [pubkey, await this.getAdmissionStatus(pubkey)] as const),
    )
    return new Map(entries)
  }
}

let port: AdmissionPort = new UnobservableAdmission()

export function admissionPort(): AdmissionPort {
  return port
}

/** Swap the implementation. Exists for tests, and for the day there is a second one. */
export function setAdmissionPort(next: AdmissionPort): void {
  port = next
}
