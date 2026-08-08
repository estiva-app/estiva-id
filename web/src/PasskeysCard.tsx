/**
 * Your passkeys, and the two operations that keep a lost laptop from becoming
 * a support ticket: enrol another device, revoke one you no longer have.
 *
 * The pair matters. Revoking a credential stops it authenticating again, but
 * any session it already minted stays valid until it expires — so signing out
 * other devices is offered right next to it rather than buried elsewhere.
 */
import { startRegistration } from '@simplewebauthn/browser'
import { useState } from 'react'
import {
  ApiError,
  type Credential,
  enrolCredentialOptions,
  listCredentials,
  revokeCredential,
  revokeOtherSessions,
  verifyCredential,
} from './api'

interface Props {
  credentials: Credential[]
  onChange: (credentials: Credential[]) => void
}

type Notice = { tone: 'ok' | 'warn' | 'error'; text: string } | null

const formatDate = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })

export function PasskeysCard({ credentials, onChange }: Props) {
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<Notice>(null)

  const isLastPasskey = credentials.length <= 1

  async function enrol() {
    setBusy('enrol')
    setNotice(null)
    try {
      const options = await enrolCredentialOptions()
      const attestation = await startRegistration({ optionsJSON: options })
      await verifyCredential(attestation)
      onChange(await listCredentials())
      setNotice({ tone: 'ok', text: 'Device enrolled. You can now sign in with it.' })
    } catch (error) {
      // A person cancelling the browser prompt is not a failure worth shouting
      // about, and it is by far the most common outcome here.
      if (error instanceof Error && error.name === 'NotAllowedError') {
        setNotice(null)
      } else {
        setNotice({
          tone: 'error',
          text: error instanceof Error ? error.message : 'Could not enrol that device',
        })
      }
    } finally {
      setBusy(null)
    }
  }

  async function revoke(credential: Credential) {
    setBusy(credential.id)
    setNotice(null)
    try {
      await revokeCredential(credential.id)
      onChange(await listCredentials())
      setNotice({
        tone: 'ok',
        text: 'Passkey revoked. Sign out other devices too if that one may still be signed in.',
      })
    } catch (error) {
      setNotice({
        tone: 'error',
        text: error instanceof ApiError ? error.message : 'Could not revoke that passkey',
      })
    } finally {
      setBusy(null)
    }
  }

  async function signOutOthers() {
    setBusy('sessions')
    setNotice(null)
    try {
      const { revoked } = await revokeOtherSessions()
      setNotice({
        tone: 'ok',
        text:
          revoked === 0
            ? 'No other sessions were signed in.'
            : `Signed out ${revoked} other session${revoked === 1 ? '' : 's'}.`,
      })
    } catch (error) {
      setNotice({
        tone: 'error',
        text: error instanceof Error ? error.message : 'Could not sign out other sessions',
      })
    } finally {
      setBusy(null)
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <h2>Your passkeys</h2>
      </div>
      <p className="card-note">
        One per device. Keeping a second one is what makes a lost laptop an inconvenience rather
        than a lockout — there is no admin-assisted recovery yet.
      </p>

      {notice && <div className={`notice ${notice.tone}`}>{notice.text}</div>}

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
            <button
              type="button"
              className="danger"
              disabled={isLastPasskey || busy !== null}
              onClick={() => revoke(credential)}
              title={
                isLastPasskey ? 'This is your only passkey. Enrol another device first.' : undefined
              }
            >
              {busy === credential.id ? 'Revoking…' : 'Revoke'}
            </button>
          </li>
        ))}
      </ul>

      {isLastPasskey && (
        <p className="hint">
          This is your only passkey, so it cannot be revoked — doing so would lock you out of your
          own identity, and there is no recovery flow yet. Enrol another device first.
        </p>
      )}

      <div className="row" style={{ marginTop: '1rem' }}>
        <button type="button" className="primary" onClick={enrol} disabled={busy !== null}>
          {busy === 'enrol' ? 'Waiting for device…' : 'Add another device'}
        </button>
        <button type="button" onClick={signOutOthers} disabled={busy !== null}>
          {busy === 'sessions' ? 'Signing out…' : 'Sign out other devices'}
        </button>
      </div>
    </section>
  )
}
