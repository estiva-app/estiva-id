/**
 * Your account (PEEK-68).
 *
 * Deliberately one page. The admin console is a separate surface (PEEK-64) and
 * this is the self-serve half — the things a person can do without asking
 * anyone: change how they appear, add a device, drop one they have lost.
 */
import { useEffect, useState } from 'react'
import { PasskeysCard } from './PasskeysCard'
import { ProfileCard } from './ProfileCard'
import {
  ApiError,
  type Credential,
  type Me,
  type Profile,
  getMe,
  getProfile,
  listCredentials,
  logout,
} from './api'

interface Loaded {
  me: Me
  profile: Profile
  credentials: Credential[]
}

type State =
  | { kind: 'loading' }
  | { kind: 'signed-out' }
  | { kind: 'error'; message: string }
  | ({ kind: 'ready' } & Loaded)

export function App() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const [me, profile, credentials] = await Promise.all([
          getMe(),
          getProfile(),
          listCredentials(),
        ])
        if (!cancelled) setState({ kind: 'ready', me, profile, credentials })
      } catch (error) {
        if (cancelled) return
        if (error instanceof ApiError && error.code === 'unauthenticated') {
          setState({ kind: 'signed-out' })
          return
        }
        setState({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not load your account',
        })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [])

  if (state.kind === 'loading') {
    return <div className="centered">Loading your account…</div>
  }

  // Sign-in itself is not built here. Registration and login exist as API
  // routes (PEEK-26) but the screens for them are not this ticket, and guessing
  // at that flow would mean two sign-in surfaces to reconcile later.
  if (state.kind === 'signed-out') {
    return (
      <div className="centered">
        <p>You are not signed in.</p>
      </div>
    )
  }

  if (state.kind === 'error') {
    return (
      <div className="centered">
        <p>{state.message}</p>
      </div>
    )
  }

  const { me, profile, credentials } = state

  return (
    <div className="page">
      <header className="page-head">
        <h1>Your account</h1>
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
      </header>

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
