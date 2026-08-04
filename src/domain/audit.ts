/**
 * The audit trail (PEEK-69).
 *
 * Stage 1 custody means the service *can* sign as anyone. The argument for
 * accepting that is not that it will not happen, but that it cannot happen
 * unseen — so every signature, every refusal and every credential change lands
 * here. That is why this exists in Stage 1 rather than later.
 *
 * Writes must never fail a request that otherwise succeeded, but a failure to
 * record must be loud: an audit gap is exactly the condition this table exists
 * to rule out.
 */
import { query } from '../db/pool.js'
import { logger } from '../logger.js'

export type AuditOutcome = 'success' | 'refused' | 'error'

export interface AuditEvent {
  actorType: 'user' | 'app' | 'system'
  actorUserId?: string | undefined
  actorClientId?: string | undefined
  action: string
  outcome: AuditOutcome
  subjectPubkey?: string | undefined
  /** Never key material, event content or PII. */
  detail?: Record<string, unknown>
  requestId?: string | undefined
}

export async function recordAudit(event: AuditEvent): Promise<void> {
  try {
    await query(
      `insert into audit_events
         (actor_type, actor_user_id, actor_client_id, action, outcome,
          subject_pubkey, detail, request_id)
       values ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        event.actorType,
        event.actorUserId ?? null,
        event.actorClientId ?? null,
        event.action,
        event.outcome,
        event.subjectPubkey ?? null,
        JSON.stringify(event.detail ?? {}),
        event.requestId ?? null,
      ],
    )
  } catch (error) {
    logger.error({ err: error, action: event.action }, 'AUDIT WRITE FAILED')
  }
}
