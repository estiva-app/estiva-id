/**
 * Reading relay membership over HTTP (PEEK-94).
 *
 * The counterpart to `relay.ts`, which only ever wrote. Until Buzz grew
 * `GET /api/members`, "is this pubkey admitted" had exactly one reader — a CLI
 * that opens the relay's own Postgres — so this service could either couple
 * itself to another system's database or answer `unknown`. It answered
 * `unknown`, for everybody, forever.
 *
 * ## Authenticated as an operator, not as the person being asked about
 *
 * The relay restricts roster reads to owners and admins, the same bar it sets
 * for minting invites. So these calls are signed with an **operator key** that
 * has been admitted at `admin` or `owner` — not with the key of whoever is
 * being looked up, who is very often precisely the person who is *not* a
 * member.
 */
import { config } from '../config.js'
import { withOperatorSecretKey } from '../domain/operator-key.js'
import { authorizationHeader } from './nip98.js'

export interface MemberRecord {
  pubkey: string
  role: string
  addedBy: string | null
  createdAt: string
}

export type MemberLookup =
  | { ok: true; admitted: boolean; role: string | null }
  /**
   * `unreachable` is kept distinct from "not admitted" on purpose. Collapsing
   * them is the one mistake that makes a half-offboarded person look fine, and
   * it is the reason this port exists at all.
   */
  | { ok: false; reason: 'unreachable' | 'forbidden' | 'not-configured'; message: string }

function membersUrl(path: string): string | null {
  const base = config().RELAY_BRIDGE_URL
  return base ? `${base}${path}` : null
}

/**
 * One pubkey's standing at the relay.
 *
 * A non-member is `admitted: false` with a `200`, not a `404` — the relay is
 * deliberate about that, because "not a member" is an answer and 404 would be
 * indistinguishable from "no such route".
 */
export async function fetchMember(pubkey: string): Promise<MemberLookup> {
  const url = membersUrl(`/api/members/${pubkey}`)
  if (!url) {
    return {
      ok: false,
      reason: 'not-configured',
      message: 'RELAY_BRIDGE_URL is not set',
    }
  }

  try {
    const response = await withOperatorSecretKey((secretKey) =>
      fetch(url, {
        headers: { authorization: authorizationHeader({ secretKey, url, method: 'GET' }) },
      }),
    )

    if (response.status === 403 || response.status === 401) {
      // The operator key is not an owner/admin at the relay — a deployment
      // fault, not a fact about the pubkey asked about. Saying "not admitted"
      // here would be inventing an answer.
      return {
        ok: false,
        reason: 'forbidden',
        message: 'the operator key is not an owner or admin at the relay',
      }
    }
    if (!response.ok) {
      return {
        ok: false,
        reason: 'unreachable',
        message: `relay answered ${response.status}`,
      }
    }

    const body = (await response.json()) as { admitted?: boolean; role?: string | null }
    return { ok: true, admitted: body.admitted === true, role: body.role ?? null }
  } catch (error) {
    return {
      ok: false,
      reason: 'unreachable',
      message: error instanceof Error ? error.message : 'could not reach the relay',
    }
  }
}

/**
 * The whole roster, in one request.
 *
 * The people list asks about everybody at once, and a per-pubkey call would be
 * N round trips to answer one screen. The roster is a workspace's worth of
 * rows, so fetching all of it and indexing locally is both smaller and simpler
 * than a batch endpoint nobody else needs.
 */
export async function fetchRoster(): Promise<
  { ok: true; members: MemberRecord[] } | { ok: false; reason: string; message: string }
> {
  const url = membersUrl('/api/members')
  if (!url) return { ok: false, reason: 'not-configured', message: 'RELAY_BRIDGE_URL is not set' }

  try {
    const response = await withOperatorSecretKey((secretKey) =>
      fetch(url, {
        headers: { authorization: authorizationHeader({ secretKey, url, method: 'GET' }) },
      }),
    )
    if (!response.ok) {
      return {
        ok: false,
        reason: response.status === 403 ? 'forbidden' : 'unreachable',
        message: `relay answered ${response.status}`,
      }
    }
    const body = (await response.json()) as { members?: MemberRecord[] }
    return { ok: true, members: body.members ?? [] }
  } catch (error) {
    return {
      ok: false,
      reason: 'unreachable',
      message: error instanceof Error ? error.message : 'could not reach the relay',
    }
  }
}
