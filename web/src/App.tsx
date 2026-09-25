/**
 * Your account (PEEK-68), and the way through to the admin console (PEEK-64).
 *
 * Two surfaces, kept apart. This is the self-serve half — the things a person
 * can do without asking anyone: change how they appear, add a device, drop one
 * they have lost. `/admin` is the other half, and answers a different question:
 * who is in this workspace, and is any of them half set up.
 */
import { useCallback, useEffect, useState } from 'react'
import { AdminPeople, AdminPerson } from './AdminPeople'
import { AuditLog } from './AuditLog'
import { BotsCard } from './BotsCard'
import { DelegationsCard } from './DelegationsCard'
import { PasskeysCard } from './PasskeysCard'
import { ProfileCard } from './ProfileCard'
import { SecurityCard } from './SecurityCard'
import { SignIn } from './SignIn'
import {
  ApiError,
  type Credential,
  type Me,
  type OwnBot,
  type Profile,
  getMe,
  getProfile,
  listCredentials,
  listOwnBots,
  logout,
} from './api'

interface Loaded {
  me: Me
  profile: Profile
  credentials: Credential[]
  bots: OwnBot[]
  botLimit: number
}

type State =
  | { kind: 'loading' }
  | { kind: 'signed-out' }
  | { kind: 'error'; message: string }
  | ({ kind: 'ready' } & Loaded)

/**
 * Where to send someone after they authenticate.
 *
 * `/authorize` bounces an unauthenticated person here with `?next=`, so this is
 * what completes the OAuth flow (PEEK-90) rather than dumping them on their
 * account page mid-redirect.
 *
 * **Only same-origin paths.** `next` is attacker-influenced, and honouring an
 * absolute URL would make this an open redirect on the origin that holds every
 * custodied key — undoing the redirect-URI allowlisting `/authorize` does. A
 * leading `//` is rejected too: `//evil.test` is protocol-relative and a
 * browser reads it as another host.
 */
function safeNext(): string | null {
  const next = new URLSearchParams(window.location.search).get('next')
  if (!next || !next.startsWith('/') || next.startsWith('//')) return null
  return next
}

/**
 * Where we are, from the address bar.
 *
 * No router library for three screens. Real paths rather than in-page state
 * because an admin looking at a person should be able to send that URL to
 * somebody — and the server already serves the app shell for any HTML GET, so a
 * deep link lands correctly on a cold load.
 */
function useRoute(): [string, (path: string) => void] {
  const [path, setPath] = useState(window.location.pathname)

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname)
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
  }, [])

  const navigate = useCallback((next: string) => {
    window.history.pushState({}, '', next)
    setPath(next)
  }, [])

  return [path, navigate]
}

export function App() {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [path, navigate] = useRoute()

  const load = useCallback(async () => {
    try {
      const [me, profile, credentials, ownBots] = await Promise.all([
        getMe(),
        getProfile(),
        listCredentials(),
        // Fails soft: a card that cannot list is still a card that can create,
        // and losing the whole account page over it would take the useful half
        // with the cosmetic one.
        listOwnBots().catch(() => ({ bots: [], limit: 0 })),
      ])
      setState({
        kind: 'ready',
        me,
        profile,
        credentials,
        bots: ownBots.bots,
        botLimit: ownBots.limit,
      })
      return true
    } catch (error) {
      if (error instanceof ApiError && error.code === 'unauthenticated') {
        setState({ kind: 'signed-out' })
        return false
      }
      setState({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Could not load your account',
      })
      return false
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  /**
   * A full navigation rather than a state change, deliberately.
   *
   * `next` points at `/authorize`, which is a *server* route that has to issue
   * a redirect — rendering it client-side would show the app shell where an
   * OAuth code should be.
   */
  const onSignedIn = useCallback(async () => {
    const next = safeNext()
    if (next) {
      window.location.assign(next)
      return
    }
    // Drop `?invite=…` and `?recover=…` from the address bar: both are spent,
    // and leaving a bearer token in history and in every screenshot afterwards
    // is careless. The recovery one matters more — it opens an existing account
    // rather than an empty new one.
    window.history.replaceState({}, '', window.location.pathname)
    await load()
  }, [load])

  if (state.kind === 'loading') {
    return <div className="centered">Loading your account…</div>
  }

  if (state.kind === 'signed-out') {
    return <SignIn onSignedIn={onSignedIn} />
  }

  if (state.kind === 'error') {
    return (
      <div className="centered">
        <p>{state.message}</p>
      </div>
    )
  }

  const { me, profile, credentials, bots, botLimit } = state

  const signOut = (
    <button
      type="button"
      className="link"
      onClick={async () => {
        await logout()
        setState({ kind: 'signed-out' })
      }}
    >
      Sign out
    </button>
  )

  if (path.startsWith('/admin')) {
    /*
      A member who types the URL is told plainly rather than shown an empty
      screen. This is presentation only — `/admin/people` refuses them on the
      server, which is the check that counts.
    */
    if (me.role !== 'admin') {
      return (
        <div className="page">
          <header className="page-head">
            <h1>Admin</h1>
            <button type="button" className="link" onClick={() => navigate('/')}>
              Your account
            </button>
          </header>
          <div className="notice warn">
            You need to be an admin to see who is in this workspace.
          </div>
        </div>
      )
    }

    /*
      **A client route must not collide with an API path.** The API routes are
      mounted before the UI catch-all, deliberately, so that a mistyped API path
      answers a JSON 404 rather than the app shell (see `http/ui.ts`). The cost
      is that any client route sharing a string with a real endpoint is
      swallowed by it — `/admin/audit` returned the audit *JSON* to a browser
      navigating there, which is why this view lives at `/admin/history` while
      its endpoint stays `/admin/audit`.

      Person ids are UUIDs and cannot collide. New literal segments here can, so
      check the route table before adding one; `ui.test.ts` pins these.
    */
    const rest = path.slice('/admin/'.length)
    const onAudit = rest === 'history'
    const personId = onAudit ? '' : rest

    return (
      <div className="page">
        <header className="page-head">
          <h1>{onAudit ? 'What happened' : 'Everyone in this workspace'}</h1>
          <div className="row">
            <button
              type="button"
              className="link"
              onClick={() => navigate(onAudit ? '/admin' : '/admin/history')}
            >
              {onAudit ? 'Everyone' : 'History'}
            </button>
            <button type="button" className="link" onClick={() => navigate('/')}>
              Your account
            </button>
            {signOut}
          </div>
        </header>

        {onAudit ? (
          <>
            <p className="card-note">
              Every privileged action this service takes or refuses. Through Stage 1 Estiva ID holds
              every private key and can sign as anyone — this is what makes that accountable rather
              than merely accepted.
            </p>
            <AuditLog />
          </>
        ) : personId ? (
          <AdminPerson id={personId} onBack={() => navigate('/admin')} />
        ) : (
          <AdminPeople onOpen={(id) => navigate(`/admin/${id}`)} />
        )}
      </div>
    )
  }

  return (
    <div className="page">
      <header className="page-head">
        <h1>Your account</h1>
        <div className="row">
          {me.role === 'admin' && (
            <button type="button" className="link" onClick={() => navigate('/admin')}>
              Admin
            </button>
          )}
          {signOut}
        </div>
      </header>

      {/*
        An invite link opened by somebody who is already signed in.
        Without saying so, they see their own account and reasonably conclude
        the invite worked — which is exactly what happens when a link meant for
        a colleague gets forwarded and opened by the wrong person.
      */}
      {new URLSearchParams(window.location.search).has('invite') && (
        <div className="notice warn">
          You are signed in as {me.email ?? 'this account'}, so that invite link was not used. If it
          was meant for somebody else, send it to them — it still works. To use it yourself, sign
          out first.
        </div>
      )}

      {/*
        The same trap for a recovery link, and worse: an invite opened by the
        wrong person creates nothing, while a recovery link opened by the wrong
        person would hand them somebody else's account.
      */}
      {new URLSearchParams(window.location.search).has('recover') && (
        <div className="notice warn">
          You are signed in as {me.email ?? 'this account'}, so that recovery link was not used. It
          is meant for whoever lost their passkeys — send it to them, and do not use it yourself.
        </div>
      )}

      {me.status !== 'active' && (
        <div className="notice warn">
          This identity is {me.status}. You can still see it, but it can no longer sign or publish.
        </div>
      )}

      <ProfileCard profile={profile} onSaved={(saved) => setState({ ...state, profile: saved })} />

      <PrivateCard me={me} profile={profile} />

      <PasskeysCard
        credentials={credentials}
        onChange={(next) => setState({ ...state, credentials: next })}
      />

      {/*
        Next to the passkeys, because both answer "what can act as me" — and a
        bot is the one that keeps acting while you are asleep (PEEK-164).
        Only for an active identity: a suspended or offboarded person making a
        bot would be a way back in, and the server refuses it anyway.
      */}
      {me.status === 'active' && (
        <BotsCard
          bots={bots}
          limit={botLimit}
          onChange={(next) => setState({ ...state, bots: next })}
        />
      )}

      {/* Beside the bots, since it is what they are doing as you (PER-22). */}
      <DelegationsCard />

      {/*
        Below the passkeys, because it is mostly about them — and because an
        admin-issued recovery is only distinguishable from an admin takeover if
        the person it happened to can see it (PEEK-67).
      */}
      <SecurityCard />
    </div>
  )
}

/**
 * What the organisation knows that the world does not.
 *
 * This card exists to be *contrasted* with the published one. Email is stored
 * here, never published to a relay and never present in a profile event — that
 * split is the point of having a private directory alongside a public profile,
 * and it is invisible unless the page draws it.
 */
function PrivateCard({ me, profile }: { me: Me; profile: Profile }) {
  return (
    <section className="card is-private">
      <div className="card-head">
        <h2>Visible only inside Estiva</h2>
        <span className="badge private">Not published</span>
      </div>
      <p className="card-note">
        Held by the identity service and never written to a relay. No app in the suite can read
        these from your profile.
      </p>

      <dl className="facts">
        <dt>Email</dt>
        <dd>{me.email ?? <span className="cred-meta">None on file</span>}</dd>

        <dt>Status</dt>
        <dd>{me.status}</dd>

        <dt>Public key</dt>
        <dd className="mono">{profile.pubkey ?? me.pubkey ?? '—'}</dd>
      </dl>
      <p className="hint">
        Your public key is not secret — it is how every app recognises you, and it appears on
        everything you write. It is here because it identifies you, not because it is hidden.
      </p>
    </section>
  )
}
