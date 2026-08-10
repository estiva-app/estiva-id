/**
 * Getting in (PEEK-68).
 *
 * One component, two modes, because they are the same screen from the person's
 * side: either you already have a passkey here or somebody sent you a link.
 * Splitting them would mean two places that both have to know what "signed in"
 * results in, and a person arriving with a stale link would hit the wrong one.
 *
 * ## No email field on sign-in
 *
 * Login is usernameless — `/auth/login/options` sends no `allowCredentials`, so
 * the authenticator offers whatever discoverable credential it holds for this
 * relying party. Asking for an email first would be a field that changes
 * nothing, and would leak whether an address is registered.
 *
 * ## The invitee does not type their own email either
 *
 * It comes from the invite and is shown, not edited. A link that let you choose
 * your own address would be transferable to anyone who found it.
 */
import { startAuthentication, startRegistration } from '@simplewebauthn/browser'
import { useEffect, useState } from 'react'
import {
  ApiError,
  type InvitePreview,
  type RecoveryPreview,
  getInvite,
  getRecovery,
  loginOptions,
  loginVerify,
  recoverOptions,
  recoverVerify,
  registerOptions,
  verifyCredential,
} from './api'

interface Props {
  /** Called once a session exists. */
  onSignedIn: () => void
}

type Mode =
  | { kind: 'sign-in' }
  | { kind: 'loading-invite'; token: string }
  | { kind: 'enrol'; token: string; invite: InvitePreview }
  | { kind: 'invite-dead'; reason: string }
  | { kind: 'loading-recovery'; token: string }
  | { kind: 'recover'; token: string; recovery: RecoveryPreview }
  | { kind: 'recovery-dead'; reason: string }

type Busy = 'sign-in' | 'enrol' | 'recover' | null

/**
 * A browser prompt the person dismissed is not an error worth shouting about,
 * and it is by far the most common outcome of both ceremonies.
 */
const cancelled = (error: unknown) => error instanceof Error && error.name === 'NotAllowedError'

function messageFor(error: unknown, fallback: string): string {
  if (error instanceof ApiError) return error.message
  return error instanceof Error ? error.message : fallback
}

const inviteProblem: Record<string, string> = {
  expired: 'That invite has expired. Ask for a new one.',
  consumed: 'That invite has already been used. Sign in instead.',
  unknown: 'That invite link is not valid.',
}

/**
 * `not_active` is deliberately not softened (PEEK-67).
 *
 * "Ask for a new link" would be wrong and would send somebody who has been
 * offboarded back to an admin who cannot help — no link recovers an identity
 * that is no longer active, and saying so is kinder than a loop.
 */
const recoveryProblem: Record<string, string> = {
  expired: 'That recovery link has expired. Ask an admin for a new one.',
  consumed: 'That recovery link has already been used. Sign in instead.',
  not_active: 'That identity is no longer active, so it cannot be recovered.',
  unknown: 'That recovery link is not valid.',
}

export function SignIn({ onSignedIn }: Props) {
  const params = new URLSearchParams(window.location.search)
  const inviteToken = params.get('invite')
  const recoveryToken = params.get('recover')

  const [mode, setMode] = useState<Mode>(() => {
    if (inviteToken) return { kind: 'loading-invite', token: inviteToken }
    if (recoveryToken) return { kind: 'loading-recovery', token: recoveryToken }
    return { kind: 'sign-in' }
  })
  const [busy, setBusy] = useState<Busy>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (mode.kind !== 'loading-invite') return
    let cancelledEffect = false
    ;(async () => {
      const result = await getInvite(mode.token).catch(() => ({
        valid: false as const,
        reason: 'unknown',
      }))
      if (cancelledEffect) return
      setMode(
        result.valid
          ? { kind: 'enrol', token: mode.token, invite: result.invite }
          : { kind: 'invite-dead', reason: result.reason },
      )
    })()
    return () => {
      cancelledEffect = true
    }
  }, [mode])

  useEffect(() => {
    if (mode.kind !== 'loading-recovery') return
    let cancelledEffect = false
    ;(async () => {
      const result = await getRecovery(mode.token).catch(() => ({
        valid: false as const,
        reason: 'unknown',
      }))
      if (cancelledEffect) return
      setMode(
        result.valid
          ? { kind: 'recover', token: mode.token, recovery: result.recovery }
          : { kind: 'recovery-dead', reason: result.reason },
      )
    })()
    return () => {
      cancelledEffect = true
    }
  }, [mode])

  async function signIn() {
    setBusy('sign-in')
    setError(null)
    try {
      const options = await loginOptions()
      const assertion = await startAuthentication({ optionsJSON: options })
      await loginVerify(assertion)
      onSignedIn()
    } catch (caught) {
      if (!cancelled(caught)) {
        // 401 here means the authenticator offered a credential this service
        // does not know — a passkey for another site, or one that was revoked.
        setError(
          caught instanceof ApiError && caught.status === 401
            ? 'That passkey is not registered here.'
            : messageFor(caught, 'Could not sign in'),
        )
      }
    } finally {
      setBusy(null)
    }
  }

  async function enrol(token: string) {
    setBusy('enrol')
    setError(null)
    try {
      const options = await registerOptions(token)
      const attestation = await startRegistration({ optionsJSON: options })
      await verifyCredential(attestation)
      onSignedIn()
    } catch (caught) {
      if (!cancelled(caught)) setError(messageFor(caught, 'Could not finish enrolling'))
    } finally {
      setBusy(null)
    }
  }

  async function recover(token: string) {
    setBusy('recover')
    setError(null)
    try {
      const options = await recoverOptions(token)
      const attestation = await startRegistration({ optionsJSON: options })
      // Its own route: this is what retires the lost passkeys and burns the
      // link, neither of which the ordinary registration route does.
      await recoverVerify(attestation)
      onSignedIn()
    } catch (caught) {
      if (!cancelled(caught)) setError(messageFor(caught, 'Could not finish recovering'))
    } finally {
      setBusy(null)
    }
  }

  if (mode.kind === 'loading-invite') {
    return <div className="centered">Checking that invite…</div>
  }

  return (
    <div className="page narrow">
      <header className="page-head">
        <h1>Estiva ID</h1>
      </header>

      {mode.kind === 'invite-dead' && (
        <section className="card">
          <div className="notice error">{inviteProblem[mode.reason] ?? inviteProblem.unknown}</div>
          <p className="card-note">
            If you already enrolled on this device, sign in below instead.
          </p>
          <button type="button" className="primary" onClick={signIn} disabled={busy !== null}>
            {busy === 'sign-in' ? 'Waiting for your passkey…' : 'Sign in with a passkey'}
          </button>
        </section>
      )}

      {mode.kind === 'loading-recovery' && <div className="centered">Checking that link…</div>}

      {mode.kind === 'recovery-dead' && (
        <section className="card">
          <div className="notice error">
            {recoveryProblem[mode.reason] ?? recoveryProblem.unknown}
          </div>
          <p className="card-note">If one of your devices still works, sign in with it instead.</p>
          <button type="button" className="primary" onClick={signIn} disabled={busy !== null}>
            {busy === 'sign-in' ? 'Waiting for your passkey…' : 'Sign in with a passkey'}
          </button>
        </section>
      )}

      {mode.kind === 'recover' && (
        <section className="card is-published">
          <div className="card-head">
            <h2>Get back into your account</h2>
          </div>
          <p className="card-note">
            An admin issued this link for <strong>{mode.recovery.email}</strong>. Enrol a passkey on
            this device and you are yourself again — <strong>your key does not change</strong>, so
            everything you have already signed stays yours.
          </p>

          <div className="notice">
            Every passkey you had before will stop working. That is the point: a device you no
            longer have should not keep access.
          </div>

          {error && <div className="notice error">{error}</div>}

          <div className="row" style={{ marginTop: '1rem' }}>
            <button
              type="button"
              className="primary"
              onClick={() => recover(mode.token)}
              disabled={busy !== null}
            >
              {busy === 'recover' ? 'Waiting for your device…' : 'Create a new passkey'}
            </button>
          </div>
          <p className="hint">
            This link works once. If it was not you who asked for it, close this page and tell an
            admin — using it hands this device your account.
          </p>
        </section>
      )}

      {mode.kind === 'enrol' && (
        <section className="card is-published">
          <div className="card-head">
            <h2>Finish setting up your account</h2>
          </div>
          <p className="card-note">
            You were invited as <strong>{mode.invite.email}</strong>. There is no password to choose
            — your device holds a passkey instead.
          </p>

          <dl className="facts">
            <dt>Email</dt>
            <dd>{mode.invite.email}</dd>
            {mode.invite.displayName && (
              <>
                <dt>Name</dt>
                <dd>{mode.invite.displayName}</dd>
              </>
            )}
            {mode.invite.handle && (
              <>
                <dt>Handle</dt>
                <dd className="mono">{mode.invite.handle}</dd>
              </>
            )}
          </dl>

          {error && <div className="notice error">{error}</div>}

          <div className="row" style={{ marginTop: '1rem' }}>
            <button
              type="button"
              className="primary"
              onClick={() => enrol(mode.token)}
              disabled={busy !== null}
            >
              {busy === 'enrol' ? 'Waiting for your device…' : 'Create my passkey'}
            </button>
          </div>
          <p className="hint">
            This link works once. Enrol a second device from your account page afterwards — there is
            no recovery if you lose your only passkey.
          </p>
        </section>
      )}

      {mode.kind === 'sign-in' && (
        <section className="card">
          <div className="card-head">
            <h2>Sign in</h2>
          </div>
          <p className="card-note">
            Your device holds the passkey. There is no password to remember, and nothing to type.
          </p>

          {error && <div className="notice error">{error}</div>}

          <button type="button" className="primary" onClick={signIn} disabled={busy !== null}>
            {busy === 'sign-in' ? 'Waiting for your passkey…' : 'Sign in with a passkey'}
          </button>

          <p className="hint">
            No account yet? Accounts here are created by invitation — ask an admin for a link.
          </p>
        </section>
      )}
    </div>
  )
}
