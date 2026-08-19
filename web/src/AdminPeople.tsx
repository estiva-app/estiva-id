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
import { type FormEvent, useCallback, useEffect, useState } from 'react'
import { AuditLog } from './AuditLog'
import {
  type AdmissionStatus,
  type AdmissionUnknownReason,
  type AdmitResult,
  ApiError,
  type CreatedInvite,
  type Credential,
  type Enrolment,
  type OffboardResult,
  type Person,
  type ReinstateResult,
  admitToRelay,
  createInvite,
  createRoleIdentity,
  getPerson,
  issueRecovery,
  issueServiceCredential,
  listPeople,
  offboardPerson,
  reinstatePerson,
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
  /*
    A role identity is not part-way through setup — setup does not apply to it.
    Without this it derives as "Never signed in", which reads as "cannot get in
    and does not know it" and sends an admin chasing a bot that works (PEEK-34).
  */
  'not-applicable': {
    label: 'Service',
    tone: 'muted',
    note: 'A role identity. It signs with a client credential and has no passkey by design.',
  },
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

/**
 * Why nobody could answer (PEEK-102).
 *
 * All four used to render as the same grey chip, which is how offboarding the
 * relay operator hid in plain sight: the console looked exactly as it had the
 * day before, and identical to a workspace with no operator at all.
 *
 * Each one names what to do, because three of the four are fixable from here or
 * from a config file and only the last is genuinely "wait".
 */
const UNKNOWN_REASON: Record<AdmissionUnknownReason, { summary: string; fix: string }> = {
  'operator-not-configured': {
    summary: 'No operator identity is configured, so admission cannot be read or changed.',
    fix: 'Set RELAY_OPERATOR_USER_ID to a role identity, and admit its pubkey at the relay as an admin.',
  },
  /*
    Split from the one above, because they are different faults with different
    fixes — and a single label sent an admin to set a variable that was already
    set. Which is the same mistake this whole table exists to stop making.
  */
  'relay-not-configured': {
    summary: 'No relay is configured, so there is nothing to ask about admission.',
    fix: 'Set RELAY_BRIDGE_URL to the workspace relay.',
  },
  'operator-inactive': {
    summary: 'The operator identity is not active here, so this service cannot ask the relay.',
    fix: 'Reinstate it from its own page. Offboarding it also withdrew its admission, which reinstating puts back.',
  },
  forbidden: {
    summary: 'The relay does not accept the operator identity as an owner or admin.',
    fix: 'Run buzz-admin add-member --role admin for the operator pubkey on the relay.',
  },
  unreachable: {
    summary: 'The relay could not be reached, so nothing here reflects its current state.',
    fix: 'This usually clears on its own. Until it does, every admission below is stale.',
  },
}

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; people: Person[]; unknownReason: AdmissionUnknownReason | null }

export function AdminPeople({ onOpen }: { onOpen: (id: string) => void }) {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [search, setSearch] = useState('')

  useEffect(() => {
    listPeople()
      .then(({ people, admissionUnknownReason }) =>
        setState({ kind: 'ready', people, unknownReason: admissionUnknownReason }),
      )
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
  // Role identities are excluded: they are never "enrolled" and never will be,
  // so counting them would put a permanent number next to "not fully set up"
  // that no action can ever clear — which teaches people to ignore it.
  const needAttention = state.people.filter(
    (person) =>
      person.kind !== 'role' && (person.enrolment !== 'enrolled' || person.status === 'offboarded'),
  ).length

  return (
    <>
      <p className="card-note">
        Everyone with an account here, plus anyone invited who has not started one.{' '}
        {state.people.length} in total
        {needAttention > 0 ? `, ${needAttention} not fully set up` : ''}.
      </p>

      {/*
        Said once, above the list, when the whole relay column is guesswork
        (PEEK-102). Not repeated per row: the cause is workspace-wide, and N
        copies of one fact would imply it was measured N times.

        It is a warning rather than a note because every "Relay:" chip below is
        meaningless while it shows — including on anybody offboarded, which is
        the case where believing the column is actively dangerous.
      */}
      {state.unknownReason && (
        <div className="notice warn">
          <strong>Relay admission cannot be read.</strong>{' '}
          {UNKNOWN_REASON[state.unknownReason].summary} Every “Relay” state below is unverified
          until this is fixed. {UNKNOWN_REASON[state.unknownReason].fix}
        </div>
      )}

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

      {/*
        Below the list rather than above it: the list is what an admin came for.
        Adding a person comes first of the two, because it is the ordinary act
        and creating a bot is rare.
      */}
      <InvitePerson />
      <NewRoleIdentity onCreated={onOpen} />
    </>
  )
}

/**
 * Adding a colleague (PEEK-65).
 *
 * The server has had `POST /invites` since invites shipped, and **nothing in
 * this app ever called it** — so the one action the admin console exists for
 * was reachable only by curl or by the bootstrap script over SSH. The people
 * list showed pending invites it gave you no way to create.
 *
 * **There is no mailer, on purpose** (Stage 1 is internal). The link comes back
 * once and the admin copies it into a DM, which is why the result is a panel
 * that stays on screen rather than a toast that passes: only the token's hash
 * is stored, so a link scrolled past is a link reissued.
 *
 * Email is the only required field. A name and a handle are the admin's to
 * reserve now or leave for the person to set later, and the role default is
 * `member` because the alternative grants this very screen.
 */
function InvitePerson() {
  const [email, setEmail] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [handle, setHandle] = useState('')
  const [role, setRole] = useState<'admin' | 'member'>('member')
  const [created, setCreated] = useState<CreatedInvite | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  async function invite(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const result = await createInvite({
        email: email.trim(),
        ...(displayName.trim() ? { displayName: displayName.trim() } : {}),
        ...(handle.trim() ? { handle: handle.trim() } : {}),
        role,
      })
      setCreated(result)
      setEmail('')
      setDisplayName('')
      setHandle('')
      setRole('member')
    } catch (caught) {
      setError(
        caught instanceof ApiError
          ? // `409` is the useful one: an address that can already sign in does
            // not need an invite, and issuing one would imply a second identity
            // for the same person.
            caught.message
          : 'Could not create that invite',
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Add a person</h2>
      </div>
      <p className="card-note">
        They get a link, open it, and enrol a passkey. <strong>No password</strong> is created or
        sent — there isn’t one in this design. Their key is minted and admitted to the relay when
        they finish.
      </p>

      {created ? (
        <>
          <div className="notice">
            Send this to {created.email} directly. It works <strong>once</strong> and expires in{' '}
            {Math.round(created.expiresInHours / 24)} days. Only its hash is stored, so it cannot be
            shown again — create another if it is lost.
          </div>
          <p className="mono">{created.url}</p>
          <div className="row">
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(created.url).then(() => setCopied(true))
              }}
            >
              {copied ? 'Copied' : 'Copy link'}
            </button>
            <button
              type="button"
              className="link"
              onClick={() => {
                setCreated(null)
                setCopied(false)
              }}
            >
              Invite somebody else
            </button>
          </div>
          <p className="hint">
            They will appear on the list above as <strong>Invited</strong> until they open it.
          </p>
        </>
      ) : (
        <>
          {error && <div className="notice error">{error}</div>}
          <form onSubmit={invite}>
            <label>
              <span className="label-text">Email</span>
              <input
                type="email"
                value={email}
                placeholder="ada@example.com"
                onChange={(event) => setEmail(event.target.value)}
              />
              <p className="hint">
                Theirs to sign in with, and never published to the relay. They cannot change it when
                enrolling — a link that let you pick would be transferable to anyone.
              </p>
            </label>
            <label>
              <span className="label-text">Name</span>
              <input
                type="text"
                value={displayName}
                placeholder="Ada Lovelace"
                onChange={(event) => setDisplayName(event.target.value)}
              />
            </label>
            <label>
              <span className="label-text">Handle</span>
              <input
                type="text"
                value={handle}
                placeholder="ada"
                onChange={(event) => setHandle(event.target.value)}
              />
              <p className="hint">
                Optional. Reserved now and published when they enrol; they can set it themselves
                later instead.
              </p>
            </label>
            <label>
              <span className="label-text">Role</span>
              <select
                value={role}
                onChange={(event) => setRole(event.target.value as 'admin' | 'member')}
              >
                <option value="member">Member</option>
                <option value="admin">Admin</option>
              </select>
              <p className="hint">
                An admin can see this screen, offboard people and invite others.
              </p>
            </label>
            <div className="row">
              <button type="submit" disabled={busy || email.trim() === ''}>
                {busy ? 'Creating…' : 'Create an invite link'}
              </button>
            </div>
          </form>
        </>
      )}
    </section>
  )
}

/**
 * Creating a bot, a `support@`, an agent (PEEK-34).
 *
 * Deliberately not part of "add a person": there is no invite, no email and no
 * passkey, because there is nobody to enrol. What comes out is a custodied key
 * with a profile and no way to sign in — and the credential that lets a
 * server-side app sign as it is minted separately, on the identity's own page,
 * because it is the part with a secret in it.
 */
function NewRoleIdentity({ onCreated }: { onCreated: (id: string) => void }) {
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function create(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const { identity } = await createRoleIdentity(name.trim())
      setName('')
      onCreated(identity.id)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not create that identity')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Add a service identity</h2>
      </div>
      <p className="card-note">
        A bot, an agent, a shared address. It gets its own key and profile like anyone else, and{' '}
        <strong>no passkey</strong> — nobody signs in as it. Mint its credential from its page
        afterwards.
      </p>

      {error && <div className="notice error">{error}</div>}

      <form onSubmit={create}>
        <label>
          <span className="label-text">Name</span>
          <input
            type="text"
            value={name}
            placeholder="Release Bot"
            onChange={(event) => setName(event.target.value)}
          />
        </label>
        <div className="row">
          <button type="submit" disabled={busy || name.trim() === ''}>
            {busy ? 'Creating…' : 'Create'}
          </button>
        </div>
      </form>
    </section>
  )
}

function PersonRow({ person, onOpen }: { person: Person; onOpen: (id: string) => void }) {
  const enrolment = ENROLMENT[person.enrolment]
  const admission = ADMISSION[person.admission]

  // An unopened invite has no account to open — no key, no passkeys, no
  // history. Everything known about it is already on this row.
  const openable = person.kind === 'user' || person.kind === 'role'

  // Somebody who never set a display name is headlined by their email, so
  // repeating it underneath is noise — and it pushes the facts that differ
  // between people off to the right.
  const name = person.displayName ?? person.email ?? 'Unnamed'
  const meta = [
    person.email === name ? null : (person.email ?? 'No email'),
    person.nip05,
    person.kind === 'role'
      ? null
      : person.lastSeenAt
        ? `last seen ${formatDate(person.lastSeenAt)}`
        : 'never seen',
  ].filter((part): part is string => part !== null)

  return (
    <li>
      <div className="person-main">
        <div className="person-name">
          {name}
          {person.role === 'admin' && <span className="badge role">Admin</span>}
          {/* Said once, plainly. A bot among people is the fact worth seeing. */}
          {person.kind === 'role' && <span className="badge role">Service</span>}
          {/*
            Not just another service identity (PEEK-102). Everything admission
            does for the whole workspace runs through this one row, and the row
            said nothing about that until somebody offboarded it and found out.
          */}
          {person.isOperator && (
            <span
              className="badge role"
              title="Relay admission for this whole workspace is driven through this identity. It cannot be offboarded."
            >
              Relay operator
            </span>
          )}
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
  | {
      kind: 'ready'
      person: Person
      credentials: Credential[]
      unknownReason: AdmissionUnknownReason | null
    }

export function AdminPerson({ id, onBack }: { id: string; onBack: () => void }) {
  const [state, setState] = useState<DetailState>({ kind: 'loading' })

  const load = useCallback(async () => {
    try {
      const { person, credentials, admissionUnknownReason } = await getPerson(id)
      setState({ kind: 'ready', person, credentials, unknownReason: admissionUnknownReason })
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

  const { person, credentials, unknownReason } = state
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
          {person.isOperator && <span className="badge role">Relay operator</span>}
        </div>

        {/*
          Stated before the facts below, because it changes how to read them:
          this identity's own admission is what every other row's admission is
          measured with (PEEK-102).
        */}
        {person.isOperator && (
          <div className="notice">
            <strong>This workspace reads and changes relay admission through this identity.</strong>{' '}
            Offboarding it is refused — it would revoke its own admission and leave nobody able to
            see or change anyone else's. To retire it, point <code>RELAY_OPERATOR_USER_ID</code> at
            another identity first.
          </div>
        )}

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
            {/*
              This used to say Buzz exposed no way to read admission, which
              stopped being true at PEEK-94 — and left the one screen that
              explains `unknown` explaining it with the wrong reason. There are
              four now, and which one it is decides what to do about it.
            */}
            {person.admission === 'unknown' && (
              <div className="cred-meta">
                {unknownReason ? (
                  <>
                    {UNKNOWN_REASON[unknownReason].summary} {UNKNOWN_REASON[unknownReason].fix}
                  </>
                ) : (
                  <>
                    This identity has no active key to ask about. Run{' '}
                    <code>buzz-admin list-members</code> on the relay to see the roster directly.
                  </>
                )}
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
            None. This person cannot sign in. Issue a recovery link below — they enrol a new passkey
            and keep the same key, so nothing they signed detaches from them.
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

      <CredentialCard person={person} />

      <AdmitCard
        person={person}
        onDone={() => {
          void load()
        }}
      />

      <ReinstateCard
        person={person}
        onDone={() => {
          void load()
        }}
      />

      <RecoveryCard person={person} />

      <OffboardCard
        person={person}
        onDone={() => {
          void load()
        }}
      />

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

/**
 * Issuing a recovery link (PEEK-67).
 *
 * The one place custody pays for itself: the person's key is unchanged, so a
 * lost laptop costs them a device rather than their history. In consumer Nostr
 * this is simply not recoverable.
 *
 * **The link is shown once and never stored**, so losing it means issuing
 * another — which supersedes the first rather than leaving two live. There is
 * no mailer in Stage 1, so an admin copies it into a DM, exactly as with an
 * invite.
 */
/**
 * The credential a bot authenticates with (PEEK-34).
 *
 * Shown only for a role identity, because issuing one for a person would be a
 * way to act as them without their passkey — refused by the server, and not
 * offered here either.
 *
 * **The secret appears once.** Only its hash is stored, so a lost secret is
 * re-minted rather than looked up, and re-minting replaces the old one rather
 * than leaving two live.
 */
function CredentialCard({ person }: { person: Person }) {
  const [issued, setIssued] = useState<{ clientId: string; clientSecret: string } | null>(null)
  const [clientId, setClientId] = useState('')
  const [kinds, setKinds] = useState('')
  const [prefixes, setPrefixes] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  if (person.kind !== 'role') return null

  async function mint(event: FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      setIssued(
        await issueServiceCredential(person.id, {
          clientId: clientId.trim(),
          name: person.displayName ?? clientId.trim(),
          allowedKinds: kinds
            .split(',')
            .map((part) => Number(part.trim()))
            .filter((kind) => Number.isInteger(kind) && kind >= 0),
          // Left blank on purpose means "whatever this deployment allows" —
          // resolved by the server, so an empty box mints a working bot rather
          // than one refused every destination.
          nip98UrlPrefixes: prefixes
            .split(',')
            .map((part) => part.trim())
            .filter((prefix) => prefix !== ''),
        }),
      )
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not mint a credential')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Service credential</h2>
      </div>
      <p className="card-note">
        A server-side app exchanges this for a short-lived token and signs as this identity. It is{' '}
        <strong>not for browser apps</strong> — a secret in a bundle is not a secret.
      </p>

      {issued ? (
        <>
          <div className="notice">
            Copy the secret now. Only its hash is stored, so it cannot be shown again — mint a new
            one if it is lost, which replaces this.
          </div>
          <dl className="facts">
            <dt>Client id</dt>
            <dd className="mono">{issued.clientId}</dd>
            <dt>Secret</dt>
            <dd className="mono">{issued.clientSecret}</dd>
          </dl>
          <div className="row">
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard.writeText(issued.clientSecret).then(() => setCopied(true))
              }}
            >
              {copied ? 'Copied' : 'Copy secret'}
            </button>
          </div>
        </>
      ) : (
        <>
          {error && <div className="notice error">{error}</div>}
          <form onSubmit={mint}>
            <label>
              <span className="label-text">Client id</span>
              <input
                type="text"
                value={clientId}
                placeholder="release-bot"
                onChange={(event) => setClientId(event.target.value)}
              />
            </label>
            <label>
              <span className="label-text">Kinds it may sign</span>
              <input
                type="text"
                value={kinds}
                placeholder="1, 9, 27235"
                onChange={(event) => setKinds(event.target.value)}
              />
              <p className="hint">
                Comma separated. The same per-app ceiling every other credential has — 27235 is
                NIP-98, without which it cannot reach the relay's bridge at all.
              </p>
            </label>
            <label>
              <span className="label-text">Where it may authenticate</span>
              <input
                type="text"
                value={prefixes}
                placeholder="Everything this deployment allows"
                onChange={(event) => setPrefixes(event.target.value)}
              />
              <p className="hint">
                Comma separated URL prefixes for 27235. Leave it blank to allow every destination
                this deployment does — narrowing here is a way to bar a bot from part of the relay,
                and it can never widen past the deployment's own list.
              </p>
            </label>
            <div className="row">
              <button type="submit" disabled={busy || clientId.trim() === ''}>
                {busy ? 'Minting…' : 'Mint a credential'}
              </button>
            </div>
          </form>
        </>
      )}
    </section>
  )
}

/**
 * Admitting somebody to the relay by hand (PEEK-65).
 *
 * Enrolment does this itself, so the button is the repair path: the relay was
 * unreachable at the moment somebody finished their passkey, and they are now
 * active here and able to read nothing in either app. Before this, the people
 * list could show "Not admitted" and offer nothing to do about it — the fix
 * lived over SSH, which is exactly the shape of gap that leaves people
 * half-onboarded for days.
 *
 * Shown only when there is something to fix. A button beside an already-admitted
 * person invites a press that does nothing and teaches an admin the screen is
 * decorative.
 */
function AdmitCard({ person, onDone }: { person: Person; onDone: () => void }) {
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<AdmitResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Only for somebody who is active here and demonstrably not admitted there.
  // `unknown` is deliberately excluded: nobody measured it, so offering a fix
  // would assert a problem that may not exist.
  if (person.status !== 'active' || person.admission !== 'not-admitted') return null

  async function admit() {
    setBusy(true)
    setError(null)
    try {
      const outcome = await admitToRelay(person.id)
      setResult(outcome)
      if (outcome.admitted) onDone()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not admit them')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Relay admission</h2>
      </div>

      <div className="notice warn">
        <strong>They have an identity here and no access to the relay.</strong> They can sign in,
        and they cannot read or write in Peek or Ship. This normally happens at enrolment; it did
        not, or it failed.
      </div>

      {result?.admitted && (
        <div className="notice ok">
          {result.alreadyAdmitted
            ? 'The relay already had them. Nothing needed changing.'
            : 'Admitted. They can read and write on the relay now.'}
        </div>
      )}

      {result && !result.admitted && (
        <>
          <div className="notice error">
            The relay did not take it ({result.reason}). Until this works, they stay locked out —
            run it by hand:
          </div>
          <div className="row">
            <code className="command">{result.command}</code>
          </div>
        </>
      )}

      {error && <div className="notice error">{error}</div>}

      {!result?.admitted && (
        <div className="row">
          <button type="button" onClick={() => void admit()} disabled={busy}>
            {busy ? 'Admitting…' : 'Admit to the relay'}
          </button>
        </div>
      )}
    </section>
  )
}

/**
 * Putting somebody back (PEEK-102).
 *
 * Offboarding shipped without a reverse, on the reasoning that a half-finished
 * *removal* is the dangerous direction. That was right about the risk and wrong
 * about the consequence: recovering from a mis-click meant an `update users set
 * status='active'` against production, which is what actually happened when a
 * QA cleanup took the relay operator with it.
 *
 * **It does not hand passkeys back**, and the card says so rather than letting
 * an admin walk away thinking the person can sign in. Offboarding revoked them
 * because the devices were leaving with somebody; a recovery link is the next
 * step, and it is on this same page.
 */
function ReinstateCard({ person, onDone }: { person: Person; onDone: () => void }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ReinstateResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  if (person.status !== 'offboarded') return null

  async function run() {
    setBusy(true)
    setError(null)
    try {
      setResult(await reinstatePerson(person.id))
      setConfirming(false)
      onDone()
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not reinstate them')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Reinstate</h2>
      </div>

      {result ? (
        <>
          <div className="notice ok">
            Their account is active again
            {result.relayAdmission.admitted ? ', and the relay admits them once more' : ''}.
          </div>

          {/*
            Said as a warning, not a footnote. "Reinstated" reads as finished,
            and an admin who stops here has left somebody active with no way to
            sign in — which looks, from the person's side, exactly like still
            being offboarded.
          */}
          {result.needsRecovery && (
            <div className="notice warn">
              <strong>They still cannot sign in.</strong> Offboarding revoked every passkey and this
              does not give them back — the devices holding them were leaving with the person. Issue
              a recovery link below so they can enrol a new one, keeping the same key.
            </div>
          )}

          {!result.relayAdmission.admitted && (
            <>
              <div className="notice error">
                The relay did not take them back ({result.relayAdmission.reason}), so they are
                active here and still shut out there. Run this:
              </div>
              <div className="row">
                <code className="command">{result.relayAdmission.command}</code>
              </div>
            </>
          )}
        </>
      ) : (
        <p className="card-note">
          Restores their account and their admission to the relay. It does <strong>not</strong>{' '}
          restore passkeys — they will need a recovery link to enrol a device, and they keep the
          same key, so nothing they signed detaches from them.
        </p>
      )}

      {error && <div className="notice error">{error}</div>}

      {!result &&
        (confirming ? (
          <div className="row">
            <button type="button" onClick={run} disabled={busy}>
              {busy ? 'Reinstating…' : `Yes, reinstate ${person.displayName ?? person.email}`}
            </button>
            <button type="button" onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </button>
          </div>
        ) : (
          <button type="button" onClick={() => setConfirming(true)}>
            Reinstate this identity
          </button>
        ))}
    </section>
  )
}

function RecoveryCard({ person }: { person: Person }) {
  const [issued, setIssued] = useState<{ url: string; expiresAt: string } | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  // Offboarding revokes every passkey, so "restore their passkey" is exactly
  // the mistake a recovery link would be. Reinstating is a status change first.
  if (person.status && person.status !== 'active') return null
  // A role has no passkey to recover, and a link that enrolled one would hand
  // whoever opened it something that signs as the bot forever (PEEK-34).
  if (person.kind === 'role') return null

  async function issue() {
    setBusy(true)
    setError(null)
    try {
      setIssued(await issueRecovery(person.id))
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not issue a recovery link')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Recovery</h2>
      </div>
      <p className="card-note">
        For somebody who has lost every device holding a passkey. They enrol a new one and{' '}
        <strong>keep the same key</strong>, so nothing they have signed detaches from them.
      </p>

      {issued ? (
        <>
          <div className="notice">
            Send this to them directly. It works once, and every passkey they had before stops
            working when they use it.
          </div>
          <p className="mono">{issued.url}</p>
          <div className="row">
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard.writeText(issued.url).then(() => setCopied(true))
              }}
            >
              {copied ? 'Copied' : 'Copy link'}
            </button>
            <span className="cred-meta">Expires {formatDate(issued.expiresAt)}</span>
          </div>
        </>
      ) : (
        <>
          {error && <div className="notice error">{error}</div>}
          <div className="row">
            <button type="button" onClick={() => void issue()} disabled={busy}>
              {busy ? 'Issuing…' : 'Issue a recovery link'}
            </button>
          </div>
          <p className="hint">
            Check who you are talking to first. This link hands whoever opens it this account.
          </p>
        </>
      )}
    </section>
  )
}

/**
 * Offboarding, and the step this service cannot take (PEEK-66).
 *
 * The button does three of the four things offboarding means: revoke every
 * passkey, disable the account and kill its sessions, withdraw the `nip05`
 * handle by republishing a profile without it. The fourth — revoking admission
 * at the relay — belongs to Buzz, which exposes no way to drive it.
 *
 * **So this refuses to report success.** A green tick with the relay still
 * accepting the person's events would be worse than no button, because it
 * converts a known manual step into an unknown one. What is shown instead is
 * the exact command, with their pubkey already in it, and it stays on the page
 * rather than passing by as a toast — the person is still half-offboarded until
 * somebody runs it, and the screen should keep saying so.
 */
function OffboardCard({ person, onDone }: { person: Person; onDone: () => void }) {
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<OffboardResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const gone = person.status === 'offboarded'

  async function run() {
    setBusy(true)
    setError(null)
    try {
      setResult(await offboardPerson(person.id))
      setConfirming(false)
      onDone()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Could not offboard')
    } finally {
      setBusy(false)
    }
  }

  /*
    The command is shown only when the relay step did *not* happen (PEEK-94).

    Before, it always did not happen, so the command was unconditional. Now a
    successful offboarding revokes admission itself — and printing "go run this"
    beside a step that already completed would send an admin to do something
    already done, which is its own kind of wrong.

    The fallback still covers a reload: an admin who refreshes after a *failed*
    relay step has no `result` in hand, and still needs somebody removed.
  */
  const admissionRevoked = result?.relayAdmission.revoked === true
  const command = admissionRevoked
    ? null
    : ((result?.relayAdmission.revoked === false ? result.relayAdmission.command : undefined) ??
      (gone && person.pubkey
        ? `docker exec buzz-prod-relay-1 buzz-admin remove-member --pubkey ${person.pubkey}`
        : null))

  return (
    <section className="card">
      <div className="card-head">
        <h2>Offboarding</h2>
      </div>

      {result && (
        <div className="notice ok">
          Revoked {result.passkeysRevoked} passkey{result.passkeysRevoked === 1 ? '' : 's'} and{' '}
          {result.sessionsRevoked} session{result.sessionsRevoked === 1 ? '' : 's'}
          {result.handleRevoked ? `, and withdrew ${result.handleRevoked}` : ''}. They can no longer
          sign in, take a token, or sign anything here.
        </div>
      )}

      {admissionRevoked && (
        <div className="notice ok">
          Their admission to the relay was withdrawn, so they can no longer read or write there
          either. All four steps are done.
        </div>
      )}

      {result && !result.attestationPublished && (
        <div className="notice error">
          The profile withdrawing their handle did not reach the relay
          {result.publishError ? ` (${result.publishError})` : ''}, so{' '}
          <strong>the handle still resolves</strong> for anyone reading the old event. Republish
          once the relay is reachable.
        </div>
      )}

      {command ? (
        <>
          <div className="notice warn">
            <strong>Not finished.</strong> The relay still admits this person
            {result?.relayAdmission.revoked === false ? ` (${result.relayAdmission.reason})` : ''}.
            Until somebody runs this, they can still read and write on the relay with the key they
            kept.
          </div>
          <div className="row">
            <code className="command">{command}</code>
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard?.writeText(command)
                setCopied(true)
              }}
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </>
      ) : (
        <p className="card-note">
          Revokes every passkey, disables the account and withdraws their handle — in one action,
          because a half-finished offboarding is the dangerous kind. It does <strong>not</strong>{' '}
          delete anything they wrote: revocation removes what they can do next, and the org keeps
          the record.
        </p>
      )}

      {error && <div className="notice error">{error}</div>}

      {/*
        The operator gets an explanation instead of a button (PEEK-102). The
        server refuses it either way, but a live button that always fails is a
        worse answer than no button — it tells an admin the action is available
        and makes them discover otherwise by trying.
      */}
      {person.isOperator && (
        <div className="notice warn">
          <strong>This identity cannot be offboarded.</strong> Admission for the whole workspace is
          driven through it, and offboarding would revoke its own — leaving nobody able to see or
          change anyone else's. Point <code>RELAY_OPERATOR_USER_ID</code> at another identity first.
        </div>
      )}

      {!gone &&
        !person.isOperator &&
        (confirming ? (
          <div className="row">
            <button type="button" className="danger" onClick={run} disabled={busy}>
              {busy ? 'Offboarding…' : `Yes, offboard ${person.displayName ?? person.email}`}
            </button>
            <button type="button" onClick={() => setConfirming(false)} disabled={busy}>
              Cancel
            </button>
          </div>
        ) : (
          <button type="button" className="danger" onClick={() => setConfirming(true)}>
            Offboard this person
          </button>
        ))}
    </section>
  )
}
