/**
 * What has happened to your access (PEEK-67).
 *
 * Recovery is mechanically identical to an admin taking somebody's account: a
 * new credential appears on an identity at an admin's instruction. Only the
 * trail distinguishes the two — and a trail only other admins can read does not
 * distinguish them *to the person it happened to*, who is the one with a reason
 * to notice and no other way of finding out.
 *
 * So this is deliberately not the admin audit view scoped to one person.
 * `/admin/audit` answers "what has happened here"; this answers "what happened
 * to me", which is a smaller question with a far larger audience — and the
 * server sends only an allowlist of actions rather than everything filtered.
 */
import { useEffect, useState } from 'react'
import { type SecurityEvent, listSecurityEvents } from './api'

/**
 * Plain descriptions, in the second person.
 *
 * `recovery.issue` is worded to be alarming when it should be: somebody asked
 * for a way into this account, and if that was not you it is the one line here
 * worth acting on.
 */
const DESCRIPTION: Record<string, string> = {
  'recovery.issue': 'A recovery link was issued for your account',
  'recovery.complete': 'Your account was recovered and a new passkey enrolled',
  'passkey.register': 'A passkey was added',
  'passkey.revoke': 'A passkey was removed',
  'session.create': 'You signed in',
  'session.revoke': 'A session was signed out',
  'user.offboard': 'This account was offboarded',
}

const formatWhen = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })

export function SecurityCard() {
  const [events, setEvents] = useState<SecurityEvent[] | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    listSecurityEvents()
      .then((loaded) => {
        if (!cancelled) setEvents(loaded)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Never a spinner in a card that is not the reason anybody opened this page.
  if (failed || events === null) return null

  return (
    <section className="card">
      <div className="card-head">
        <h2>Recent account activity</h2>
      </div>
      <p className="card-note">
        Changes to how this account is accessed. If something here was not you — especially a
        recovery link — tell an admin.
      </p>

      {/* Same list treatment as the passkeys above: description left, when right. */}
      {events.length === 0 ? (
        <p className="hint">Nothing yet.</p>
      ) : (
        <ul className="credentials">
          {events.map((event) => (
            <li key={event.id}>
              <div className="row">
                <span>{DESCRIPTION[event.action] ?? event.action}</span>
                {/*
                  The one distinction that matters on this screen. "A passkey was
                  added" is unremarkable when you added it and is the whole story
                  when somebody else did.
                */}
                {event.bySomeoneElse && (
                  <span className="badge role">
                    by {event.actorDisplayName ?? event.actorEmail ?? 'an admin'}
                  </span>
                )}
                {event.outcome !== 'success' && <span className="badge">{event.outcome}</span>}
              </div>
              <div className="cred-meta">{formatWhen(event.occurredAt)}</div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
