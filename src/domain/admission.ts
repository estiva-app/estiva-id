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
 * ## There are two implementations now (PEEK-94)
 *
 * For most of this service's life there was no way to ask: the relay's HTTP
 * surface had no membership read endpoint, and the only reader was a CLI that
 * opened Buzz's own Postgres. Answering meant coupling to another service's
 * database — the coupling ARCHITECTURE.md §3 exists to refuse — so the answer
 * was `unknown`, for everybody, always.
 *
 * Buzz now serves `GET /api/members`, and {@link RelayAdmission} asks it. The
 * roster is fetched once and indexed, because the people list asks about
 * everybody at once and a per-pubkey call would be N round trips for one screen.
 *
 * **`unknown` did not go away, and must not.** A relay that cannot be reached,
 * or an operator key that has not been admitted, still produces it — and it
 * still means "nobody measured this", never "probably fine". Collapsing it into
 * `not-admitted` would invent a fact; collapsing it into `admitted` is the one
 * reading that makes a half-offboarded person look safe.
 */

import { fetchMember, fetchRoster } from '../nostr/members.js'
import { operatorConfigured } from './operator-key.js'

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

/**
 * The real one: ask the relay (PEEK-94).
 *
 * Every failure degrades to `unknown` rather than throwing. A people list that
 * five-hundreds because the relay is briefly unreachable is worse than one
 * that says it does not know — the identity half of every row is still true and
 * still worth showing, and this column has always been allowed to say nothing.
 */
export class RelayAdmission implements AdmissionPort {
  async getAdmissionStatus(pubkey: string): Promise<AdmissionStatus> {
    const result = await fetchMember(pubkey)
    if (!result.ok) return 'unknown'
    return result.admitted ? 'admitted' : 'not-admitted'
  }

  async getAdmissionStatuses(pubkeys: readonly string[]): Promise<Map<string, AdmissionStatus>> {
    if (pubkeys.length === 0) return new Map()

    // One roster read, then a local index. Asking per pubkey would be N
    // authenticated round trips to paint one screen, and the roster is a
    // workspace's worth of rows.
    const roster = await fetchRoster()
    if (!roster.ok) return new Map(pubkeys.map((pubkey) => [pubkey, 'unknown' as const]))

    const admitted = new Set(roster.members.map((member) => member.pubkey.toLowerCase()))
    return new Map(
      pubkeys.map((pubkey) => [
        pubkey,
        admitted.has(pubkey.toLowerCase()) ? ('admitted' as const) : ('not-admitted' as const),
      ]),
    )
  }
}

/**
 * Which implementation is live depends on whether an operator identity exists.
 *
 * Without one there is nothing to authenticate a roster read with, so the
 * honest answer is still `unknown` — the pre-PEEK-94 behaviour, reached
 * deliberately rather than by failing.
 */
let port: AdmissionPort = operatorConfigured() ? new RelayAdmission() : new UnobservableAdmission()

export function admissionPort(): AdmissionPort {
  return port
}

/** Swap the implementation. Exists for tests, and for the day there is a second one. */
export function setAdmissionPort(next: AdmissionPort): void {
  port = next
}
