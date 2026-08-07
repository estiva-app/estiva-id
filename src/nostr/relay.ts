/**
 * Client for Buzz's HTTP bridge.
 *
 * Only `POST /events` is here. Estiva ID publishes; it does not read the relay
 * back, because the relay is not the record — Postgres is. Adding `/query`
 * before something needs it would be inventing a second source of truth for
 * profile state.
 */
import { config } from '../config.js'
import type { SignedEvent } from './event.js'
import { authorizationHeader } from './nip98.js'

/** Where to publish. Publishing is OFF unless this is set — that is the flag. */
export function relayBridgeUrl(): string | null {
  return config().RELAY_BRIDGE_URL || null
}

export interface PublishResult {
  ok: boolean
  eventId?: string
  /** Set when the relay declined. `duplicate` is called out separately below. */
  reason?: string
  /** True when the relay already had this state — not a failure. */
  duplicate?: boolean
  httpStatus: number
}

/**
 * Publish one signed event.
 *
 * **HTTP 200 does not mean accepted.** The relay answers a duplicate with
 * `200 {"accepted":false,"message":"duplicate: …"}`, so checking only the
 * status code silently records rejections as successes — the `accepted` field
 * is authoritative. Established against a running relay by Peek's bridge
 * client, not inferred from the source.
 */
export async function publishEvent(
  event: SignedEvent,
  secretKey: Buffer,
  options: { signal?: AbortSignal } = {},
): Promise<PublishResult> {
  const base = relayBridgeUrl()
  if (!base) throw new Error('RELAY_BRIDGE_URL is not set')

  const url = `${base}/events`
  const body = JSON.stringify(event)

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // Rebuilt per call, and unique per call — see nip98.ts on the nonce.
      authorization: authorizationHeader({ secretKey, url, method: 'POST', body }),
    },
    body,
    signal: options.signal,
  })

  const status = response.status
  const text = await response.text()

  let parsed: { accepted?: boolean; event_id?: string; message?: string; error?: string } = {}
  try {
    parsed = JSON.parse(text)
  } catch {
    return { ok: false, reason: `unparseable response: ${text.slice(0, 200)}`, httpStatus: status }
  }

  if (status < 200 || status >= 300) {
    return { ok: false, reason: parsed.error ?? text.slice(0, 200), httpStatus: status }
  }

  if (parsed.accepted === false) {
    // "already exists" is the desired end state, so callers treat it as success.
    const duplicate = (parsed.message ?? '').startsWith('duplicate:')
    return {
      ok: duplicate,
      duplicate,
      eventId: parsed.event_id,
      reason: parsed.message,
      httpStatus: status,
    }
  }

  return { ok: true, eventId: parsed.event_id, httpStatus: status }
}
