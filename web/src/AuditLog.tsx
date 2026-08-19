/**
 * What happened, and who did it (PEEK-69).
 *
 * The table behind this has been written since the service was built and read
 * by nobody. That mattered more than it sounds: through Stage 1 this service
 * can sign as anyone, and the argument for accepting that is not "it will not
 * happen" but "it cannot happen unseen" — which was resting on a table with no
 * viewer.
 *
 * ## What the rows are shaped around
 *
 * Every line answers **who did it, to whom, and when**, in that order, because
 * that is the sentence somebody reads a log to complete. The action is rendered
 * as a phrase rather than its dotted verb: `user.status_change` tells you
 * nothing at a glance, "offboarded" tells you everything.
 *
 * Refusals are shown, not filtered out. A refused signature is the log doing its
 * job — an app asking for something it may not have — and a log that shows only
 * successes cannot distinguish "nothing happened" from "everything was blocked".
 */

import { IconArrowRight } from '@tabler/icons-react'
import { useCallback, useEffect, useState } from 'react'
import { Select } from './Select'
import { ApiError, type AuditEntry, listAudit } from './api'

const formatWhen = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })

/**
 * The dotted verb, as a phrase.
 *
 * Anything not listed falls back to the raw action rather than being hidden —
 * an unrecognised action is exactly the thing a reader most needs to see, and a
 * log that silently drops what it does not understand is worse than one that
 * prints a slug.
 */
const PHRASE: Record<string, string> = {
  'user.status_change': 'changed status',
  'invite.create': 'invited somebody',
  'passkey.register': 'added a passkey',
  'passkey.revoke': 'revoked a passkey',
  'session.create': 'signed in',
  'session.revoke': 'signed out',
  'session.revoke_others': 'signed out other devices',
  'token.issue': 'took a token',
  'token.exchange': 'exchanged a code for a token',
  'authorize.issue': 'authorised an app',
  'sign.granted': 'signed an event',
  'sign.refused': 'was refused a signature',
  'profile.publish': 'published a profile',
  'avatar.upload': 'uploaded an avatar',
}

function describe(entry: AuditEntry): string {
  const phrase = PHRASE[entry.action] ?? entry.action
  if (entry.action === 'user.status_change') {
    const { from, to } = entry.detail as { from?: string; to?: string }
    return to === 'active' ? `restored access (was ${from})` : `set status to ${to} (was ${from})`
  }
  return phrase
}

const nameOf = (displayName: string | null, email: string | null, fallback: string): string =>
  displayName ?? email ?? fallback

interface Props {
  /** Scope to one person: what they did, and what was done to them. */
  person?: string
  /** Fewer rows and no filter, for the panel on a person's page. */
  compact?: boolean
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; entries: AuditEntry[]; nextBefore: string | null; actions: string[] }

export function AuditLog({ person, compact = false }: Props) {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [action, setAction] = useState('')
  const [loadingMore, setLoadingMore] = useState(false)

  const load = useCallback(async () => {
    setState({ kind: 'loading' })
    try {
      const page = await listAudit({
        ...(person ? { person } : {}),
        ...(action ? { action } : {}),
      })
      setState({ kind: 'ready', ...page })
    } catch (error) {
      setState({
        kind: 'error',
        message:
          error instanceof ApiError && error.code === 'forbidden'
            ? 'You need to be an admin to see this.'
            : 'Could not load the log.',
      })
    }
  }, [person, action])

  useEffect(() => {
    void load()
  }, [load])

  async function more() {
    if (state.kind !== 'ready' || !state.nextBefore) return
    setLoadingMore(true)
    try {
      const page = await listAudit({
        ...(person ? { person } : {}),
        ...(action ? { action } : {}),
        before: state.nextBefore,
      })
      setState({
        kind: 'ready',
        entries: [...state.entries, ...page.entries],
        nextBefore: page.entries.length === 0 ? null : page.nextBefore,
        actions: state.actions,
      })
    } finally {
      setLoadingMore(false)
    }
  }

  if (state.kind === 'loading') return <p className="hint">Loading…</p>
  if (state.kind === 'error') return <p className="hint error">{state.message}</p>

  return (
    <>
      {!compact && (
        <div className="row" style={{ marginBottom: '1rem' }}>
          <div className="field" style={{ margin: 0 }}>
            <span className="label-text">Action</span>
            <Select
              value={action}
              ariaLabel="Action"
              onChange={setAction}
              options={[
                { value: '', label: 'Everything' },
                ...state.actions.map((name) => ({ value: name, label: PHRASE[name] ?? name })),
              ]}
            />
          </div>
        </div>
      )}

      {state.entries.length === 0 ? (
        <p className="hint">Nothing recorded yet.</p>
      ) : (
        <ul className="audit">
          {state.entries.map((entry) => (
            <AuditRow key={entry.id} entry={entry} showSubject={person === undefined} />
          ))}
        </ul>
      )}

      {state.nextBefore && state.entries.length > 0 && (
        <button type="button" onClick={more} disabled={loadingMore} style={{ marginTop: '0.8rem' }}>
          {loadingMore ? 'Loading…' : 'Show older'}
        </button>
      )}
    </>
  )
}

function AuditRow({ entry, showSubject }: { entry: AuditEntry; showSubject: boolean }) {
  // An app acting is not a person acting, and conflating them would hide the
  // one case worth noticing: this service acting on its own.
  const actor =
    entry.actorType === 'app'
      ? (entry.actorClientId ?? 'an app')
      : entry.actorType === 'system'
        ? 'Estiva ID'
        : nameOf(entry.actorDisplayName, entry.actorEmail, 'someone')

  const subject = nameOf(entry.subjectDisplayName, entry.subjectEmail, '')
  // Only when it adds something: an action somebody did to themselves reads
  // worse as "Ada signed in — Ada" than as "Ada signed in".
  const showTo = showSubject && subject !== '' && entry.subjectUserId !== entry.actorUserId

  return (
    <li>
      <div className="audit-line">
        <span className="audit-actor">{actor}</span> {describe(entry)}
        {showTo && (
          <>
            <IconArrowRight size={14} stroke={1.5} className="audit-arrow" />
            <span className="audit-subject">{subject}</span>
          </>
        )}
        {entry.outcome !== 'success' && (
          <span className={`chip ${chipFor(entry.outcome)}`}>{entry.outcome}</span>
        )}
      </div>
      <div className="cred-meta">
        {formatWhen(entry.occurredAt)}
        {reasonOf(entry) ? ` · ${reasonOf(entry)}` : ''}
      </div>
    </li>
  )
}

const chipFor = (outcome: AuditEntry['outcome']) => (outcome === 'refused' ? 'warn' : 'danger')

/**
 * The `reason` an entry carries, when it has one.
 *
 * Surfaced because it is the whole value of a refusal: `kind_profile_forbidden`
 * says an app tried to publish a profile and was stopped, which is a materially
 * different event from a token expiring.
 */
function reasonOf(entry: AuditEntry): string | null {
  const reason = (entry.detail as { reason?: unknown }).reason
  return typeof reason === 'string' ? reason : null
}
