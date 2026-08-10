/**
 * Reading the audit trail (PEEK-69).
 *
 * The table has been written since the service was built. Nothing has ever read
 * it, and until something did, the argument that custody is acceptable because
 * misuse "cannot happen unseen" was resting on a table nobody could see.
 *
 * ## Who did it, to whom, and when
 *
 * Those three are the whole requirement, and only the first and last were easy.
 * `actor_user_id` names the actor. Time is `occurred_at`. **The subject is
 * `subject_pubkey`**, which needs resolving back to a person before it means
 * anything to a human reading a screen.
 *
 * That resolution goes through `user_keys` rather than a `subject_user_id`
 * column, deliberately:
 *
 *   * a person's key rows are kept when they rotate (`status = 'rotated'`), so
 *     joining on the key still names the right person for an old record — which
 *     a denormalised id would also do, but only if every writer remembered to
 *     set it;
 *   * every writer already sets `subject_pubkey`, and adding a column means
 *     every existing row has a null in it forever.
 *
 * A person's history is therefore **what they did plus what was done to them**,
 * which is also the more useful question: "show me this account" should include
 * the admin who offboarded it, not just the things the account did itself.
 */
import { query } from '../db/pool.js'

export interface AuditEntry {
  id: string
  occurredAt: string
  actorType: 'user' | 'app' | 'system'
  /** Null for a system action, or an actor whose account was since deleted. */
  actorUserId: string | null
  actorEmail: string | null
  actorDisplayName: string | null
  /** The app, when one acted — `/sign` and `/token` are called by apps. */
  actorClientId: string | null
  action: string
  outcome: 'success' | 'refused' | 'error'
  subjectPubkey: string | null
  /** Resolved from the pubkey, so a screen can name the person acted upon. */
  subjectUserId: string | null
  subjectEmail: string | null
  subjectDisplayName: string | null
  detail: Record<string, unknown>
}

export interface AuditQuery {
  /** Everything this person did, and everything done to them. */
  userId?: string | undefined
  /** Exact action, e.g. `user.status_change`. */
  action?: string | undefined
  /** Keyset pagination: return entries older than this id. */
  before?: string | undefined
  limit?: number | undefined
}

/** A page size that fits a screen, and a ceiling a caller cannot argue with. */
const DEFAULT_LIMIT = 50
const MAX_LIMIT = 200

/**
 * The page size actually used, after defaults and clamping.
 *
 * Exported because a caller cannot otherwise tell a full page from the last
 * one, and offering "show older" at the end of the log is a button that
 * answers with nothing.
 */
export function effectiveLimit(requested?: number): number {
  return Math.min(Math.max(requested ?? DEFAULT_LIMIT, 1), MAX_LIMIT)
}

interface Row {
  id: string
  occurred_at: Date
  actor_type: AuditEntry['actorType']
  actor_user_id: string | null
  actor_email: string | null
  actor_display_name: string | null
  actor_client_id: string | null
  action: string
  outcome: AuditEntry['outcome']
  subject_pubkey: string | null
  subject_user_id: string | null
  subject_email: string | null
  subject_display_name: string | null
  detail: Record<string, unknown>
}

/**
 * Newest first, keyset-paginated.
 *
 * By `id` rather than by `occurred_at`: the timestamp is not unique — a request
 * can write several rows in the same millisecond, and `sign.refused` next to the
 * `token.issue` that preceded it is exactly that case — so an offset or a
 * timestamp cursor drops or repeats rows at a page boundary. `id` is a
 * `bigserial` and monotonic, which is the property paging actually needs.
 */
export async function listAudit(filter: AuditQuery = {}): Promise<AuditEntry[]> {
  const limit = effectiveLimit(filter.limit)

  const result = await query<Row>(
    `select a.id::text,
            a.occurred_at,
            a.actor_type,
            a.actor_user_id,
            actor.email        as actor_email,
            actor.display_name as actor_display_name,
            a.actor_client_id,
            a.action,
            a.outcome,
            a.subject_pubkey,
            subject.id           as subject_user_id,
            subject.email        as subject_email,
            subject.display_name as subject_display_name,
            a.detail
       from audit_events a
       left join users actor on actor.id = a.actor_user_id
       -- Any key, not just the active one: a record written before a rotation
       -- still names the person it was about.
       left join user_keys sk on sk.pubkey = a.subject_pubkey
       left join users subject on subject.id = sk.user_id
      where ($1::uuid is null
             or a.actor_user_id = $1::uuid
             or sk.user_id = $1::uuid)
        and ($2::text is null or a.action = $2::text)
        and ($3::bigint is null or a.id < $3::bigint)
      order by a.id desc
      limit $4`,
    [filter.userId ?? null, filter.action ?? null, filter.before ?? null, limit],
  )

  return result.rows.map((row) => ({
    id: row.id,
    occurredAt: row.occurred_at.toISOString(),
    actorType: row.actor_type,
    actorUserId: row.actor_user_id,
    actorEmail: row.actor_email,
    actorDisplayName: row.actor_display_name,
    actorClientId: row.actor_client_id,
    action: row.action,
    outcome: row.outcome,
    subjectPubkey: row.subject_pubkey,
    subjectUserId: row.subject_user_id,
    subjectEmail: row.subject_email,
    subjectDisplayName: row.subject_display_name,
    detail: row.detail,
  }))
}

/** The distinct actions present, so a filter can offer real values. */
export async function auditActions(): Promise<string[]> {
  const result = await query<{ action: string }>(
    'select distinct action from audit_events order by action',
  )
  return result.rows.map((row) => row.action)
}
