/**
 * The people list (PEEK-64).
 *
 * Nothing answered "who is in this workspace" for a human before this screen.
 * The rest of the admin surface hangs off it — offboarding in one action and
 * adding a person both start from a row here.
 *
 * ## What this screen is actually for
 *
 * Not a table of accounts. It is the one place where **this service's view of a
 * person and the relay's view sit side by side**, because the mismatch between
 * them is the thing worth seeing and neither system surfaces it alone:
 *
 * * *Half-onboarded* — an identity exists and was never admitted to the relay.
 *   Annoying; they cannot publish, somebody complains on day one.
 * * *Half-offboarded* — removed here, still admitted at the relay. A security
 *   problem, and a silent one.
 *
 * So the row draws three things that are usually collapsed into one: account
 * status, how far enrolment got, and admission. A person is only "fine" when all
 * three agree, and this screen refuses to imply that when they do not.
 */
import { useCallback, useEffect, useState } from 'react'
import { AuditLog } from './AuditLog'
import {
  type AdmissionStatus,
  ApiError,
  type Credential,
  type Enrolment,
  type Person,
  getPerson,
  listPeople,
} from './api'

const formatDate = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })

/**
 * How each enrolment state is named to an admin.
 *
 * "Never signed in" rather than "enrolling", because the useful fact is not
 * which step they are on — it is that this person cannot get in and does not
 * know it.
 */
const ENROLMENT: Record<Enrolment, { label: string; tone: string; note: string }> = {
  invited: {
    label: 'Invited',
    tone: 'pending',
    note: 'Sent a link. They have not opened it yet, so no account exists.',
  },
  enrolling: {
    label: 'Never signed in',
    tone: 'warn',
    note: 'They opened the link and never finished adding a passkey. The account and its key exist; they cannot sign in.',
  },
  enrolled: { label: 'Enrolled', tone: 'ok', note: 'Has at least one passkey.' },
}

/**
 * Admission is rendered as its own thing, never folded into the status column.
 *
 * `unknown` gets a plain, honest label. It is not a warning — nothing is
 * necessarily wrong — but it is also not silence, because "we cannot see" and
 * "it is fine" are different facts and only one of them is true here.
 */
const ADMISSION: Record<AdmissionStatus, { label: string; tone: string }> = {
  admitted: { label: 'Admitted', tone: 'ok' },
  'not-admitted': { label: 'Not admitted', tone: 'warn' },
  unknown: { label: 'Not known', tone: 'muted' },
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; people: Person[] }

export function AdminPeople({ onOpen }: { onOpen: (id: string) => void }) {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [search, setSearch] = useState('')

  useEffect(() => {
    listPeople()
      .then((people) => setState({ kind: 'ready', people }))
      .catch((error: unknown) =>
        setState({
          kind: 'error',
          message:
            error instanceof ApiError && error.code === 'forbidden'
              ? 'You need to be an admin to see this.'
              : 'Could not load the directory.',
        }),
      )
  }, [])

  if (state.kind === 'loading') return <div className="centered">Loading the directory…</div>
  if (state.kind === 'error') return <div className="centered">{state.message}</div>

  const needle = search.trim().toLowerCase()
  const shown = needle
    ? state.people.filter((person) =>
        [person.displayName, person.email, person.handle, person.pubkey]
          .filter((field): field is string => field !== null)
          .some((field) => field.toLowerCase().includes(needle)),
      )
    : state.people

  // Counted from everyone, not from the filtered view: a summary that changes
  // as you type is describing your search rather than your workspace.
  const needAttention = state.people.filter(
    (person) => person.enrolment !== 'enrolled' || person.status === 'offboarded',
  ).length

  return (
    <>
      <p className="card-note">
        Everyone with an account here, plus anyone invited who has not started one.{' '}
        {state.people.length} in total
        {needAttention > 0 ? `, ${needAttention} not fully set up` : ''}.
      </p>

      <label>
        <span className="label-text">Search</span>
        <input
          type="text"
          value={search}
          placeholder="Name, email, handle or public key"
          onChange={(event) => setSearch(event.target.value)}
        />
      </label>

      {shown.length === 0 && <p className="hint">Nobody matches “{search}”.</p>}

      <ul className="people">
        {shown.map((person) => (
          <PersonRow key={`${person.kind}:${person.id}`} person={person} onOpen={onOpen} />
        ))}
      </ul>
    </>
  )
}

function PersonRow({ person, onOpen }: { person: Person; onOpen: (id: string) => void }) {
  const enrolment = ENROLMENT[person.enrolment]
  const admission = ADMISSION[person.admission]

  // An unopened invite has no account to open — no key, no passkeys, no
  // history. Everything known about it is already on this row.
  const openable = person.kind === 'user'

  // Somebody who never set a display name is headlined by their email, so
  // repeating it underneath is noise — and it pushes the facts that differ
  // between people off to the right.
  const name = person.displayName ?? person.email ?? 'Unnamed'
  const meta = [
    person.email === name ? null : (person.email ?? 'No email'),
    person.nip05,
    person.lastSeenAt ? `last seen ${formatDate(person.lastSeenAt)}` : 'never seen',
  ].filter((part): part is string => part !== null)

  return (
    <li>
      <div className="person-main">
        <div className="person-name">
          {name}
          {person.role === 'admin' && <span className="badge role">Admin</span>}
        </div>
        <div className="cred-meta">{meta.join(' · ')}</div>
      </div>

      <div className="person-states">
        {/*
          Account status is only drawn when it is not the ordinary one. An
          "active" chip on every row trains people to stop reading the column,
          which is the column where "offboarded" has to be noticed.
        */}
        {person.status && person.status !== 'active' && (
          <span className="chip danger" title="This identity can no longer sign or publish here.">
            {person.status}
          </span>
        )}
        <span className={`chip ${enrolment.tone}`} title={enrolment.note}>
          {enrolment.label}
        </span>
        <span
          className={`chip ${admission.tone}`}
          title={
            person.admission === 'unknown'
              ? 'The relay does not expose a way to read membership, so this cannot be checked from here.'
              : 'Whether the relay will accept events from this key.'
          }
        >
          Relay: {admission.label}
        </span>
        {openable && (
          <button type="button" className="link" onClick={() => onOpen(person.id)}>
            Open
          </button>
        )}
      </div>
    </li>
  )
}

type DetailState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; person: Person; credentials: Credential[] }

export function AdminPerson({ id, onBack }: { id: string; onBack: () => void }) {
  const [state, setState] = useState<DetailState>({ kind: 'loading' })

  const load = useCallback(async () => {
    try {
      const { person, credentials } = await getPerson(id)
      setState({ kind: 'ready', person, credentials })
    } catch (error) {
      setState({
        kind: 'error',
        message:
          error instanceof ApiError && error.code === 'not_found'
            ? 'No such person.'
            : 'Could not load that person.',
      })
    }
  }, [id])

  useEffect(() => {
    void load()
  }, [load])

  if (state.kind === 'loading') return <div className="centered">Loading…</div>
  if (state.kind === 'error') {
    return (
      <div className="centered">
        <p>{state.message}</p>
        <button type="button" className="link" onClick={onBack}>
          Back to everyone
        </button>
      </div>
    )
  }

  const { person, credentials } = state
  const enrolment = ENROLMENT[person.enrolment]
  const admission = ADMISSION[person.admission]

  return (
    <>
      <button type="button" className="link" onClick={onBack}>
        ← Back to everyone
      </button>

      <section className="card" style={{ marginTop: '1rem' }}>
        <div className="card-head">
          <h2>{person.displayName ?? person.email ?? 'Unnamed'}</h2>
          {person.role === 'admin' && <span className="badge role">Admin</span>}
        </div>

        <dl className="facts">
          <dt>Email</dt>
          <dd>{person.email ?? <span className="cred-meta">None on file</span>}</dd>

          <dt>Handle</dt>
          <dd>{person.nip05 ?? <span className="cred-meta">None</span>}</dd>

          <dt>Public key</dt>
          <dd className="mono">{person.pubkey ?? '—'}</dd>

          <dt>Status here</dt>
          <dd>{person.status ?? '—'}</dd>

          <dt>Enrolment</dt>
          <dd>
            {enrolment.label}
            <div className="cred-meta">{enrolment.note}</div>
          </dd>

          <dt>Relay</dt>
          <dd>
            {admission.label}
            {person.admission === 'unknown' && (
              <div className="cred-meta">
                Buzz owns admission and exposes no way to read it, so this service cannot check it.
                Run <code>buzz-admin list-members</code> on the relay to see the truth.
              </div>
            )}
          </dd>

          <dt>Added</dt>
          <dd>{formatDate(person.createdAt)}</dd>

          <dt>Last seen</dt>
          <dd>{person.lastSeenAt ? formatDate(person.lastSeenAt) : 'Never'}</dd>
        </dl>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Passkeys</h2>
        </div>
        <p className="card-note">
          Labels and dates only. No public keys and no credential ids — an admin needs to know a
          device exists, not what is inside it.
        </p>

        {credentials.length === 0 ? (
          <p className="hint">
            None. This person cannot sign in, and will need a fresh invite — there is no
            admin-assisted recovery yet.
          </p>
        ) : null}
        {credentials.length > 0 && (
          <ul className="credentials">
            {credentials.map((credential) => (
              <li key={credential.id}>
                <div>
                  <div>{credential.nickname ?? credential.deviceType ?? 'Passkey'}</div>
                  <div className="cred-meta">
                    Added {formatDate(credential.createdAt)}
                    {credential.lastUsedAt
                      ? ` · last used ${formatDate(credential.lastUsedAt)}`
                      : ' · never used'}
                    {credential.backedUp ? ' · synced' : ' · this device only'}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>

      {/*
        Both directions on purpose: what this person did, and what was done to
        them. "Who offboarded this account" is the question an admin opens a
        history for, and it is not an action the account itself took.
      */}
      <section className="card">
        <div className="card-head">
          <h2>History</h2>
        </div>
        <p className="card-note">What this person did, and what was done to them.</p>
        <AuditLog person={person.id} compact />
      </section>
    </>
  )
}
