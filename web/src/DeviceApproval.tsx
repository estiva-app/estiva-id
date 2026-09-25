/**
 * Approving a bot to act as you (PER-22).
 *
 * The page a bot's `verification_uri_complete` opens. It needs no session: the
 * passkey prompt *is* the authentication, over a challenge bound to this one
 * request, and the server accepts only the bot's owner. So a person who is not
 * signed in approves in one step, and one who is signed in as somebody else
 * cannot approve by accident.
 *
 * It says plainly what approving grants, because this is the one screen in the
 * suite that hands another party your identity: a day of your apps, writes
 * included, every event tagged with the bot's name, revocable from your account.
 */
import { startAuthentication } from '@simplewebauthn/browser'
import { useEffect, useState } from 'react'
import {
  type DeviceRequest,
  approveDeviceRequest,
  denyDeviceRequest,
  deviceApprovalOptions,
  getDeviceRequest,
} from './api'

type State =
  | { kind: 'loading' }
  | { kind: 'enter' }
  | { kind: 'missing'; message: string }
  | { kind: 'ready'; request: DeviceRequest }
  | { kind: 'approved'; botName: string }
  | { kind: 'denied' }

export function DeviceApproval({ initialCode }: { initialCode: string | null }) {
  const [code, setCode] = useState(initialCode ?? '')
  const [state, setState] = useState<State>(initialCode ? { kind: 'loading' } : { kind: 'enter' })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const lookUp = async (value: string) => {
    setError(null)
    setState({ kind: 'loading' })
    try {
      setState({ kind: 'ready', request: await getDeviceRequest(value) })
    } catch (failure) {
      setState({
        kind: 'missing',
        message: failure instanceof Error ? failure.message : 'That code is not valid.',
      })
    }
  }

  // biome-ignore lint/correctness/useExhaustiveDependencies: once, for the code in the link.
  useEffect(() => {
    if (initialCode) void lookUp(initialCode)
  }, [])

  const approve = async (request: DeviceRequest) => {
    setBusy(true)
    setError(null)
    try {
      const options = await deviceApprovalOptions(request.userCode)
      const assertion = await startAuthentication({ optionsJSON: options })
      const result = await approveDeviceRequest(request.userCode, assertion)
      setState({ kind: 'approved', botName: result.botName })
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Approval failed')
    } finally {
      setBusy(false)
    }
  }

  const deny = async (request: DeviceRequest) => {
    setBusy(true)
    try {
      await denyDeviceRequest(request.userCode)
      setState({ kind: 'denied' })
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not deny the request')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="page narrow">
      <section className="card">
        <div className="card-head">
          <h2>Let a bot act as you</h2>
        </div>

        {state.kind === 'loading' && <p className="card-note">Looking up the request…</p>}

        {(state.kind === 'enter' || state.kind === 'missing') && (
          <form
            onSubmit={(event) => {
              event.preventDefault()
              void lookUp(code)
            }}
          >
            {state.kind === 'missing' && <p className="notice error">{state.message}</p>}
            <label>
              Code shown by the bot
              <input
                value={code}
                onChange={(event) => setCode(event.target.value)}
                placeholder="BCDF-GHJK"
                autoComplete="off"
              />
            </label>
            <button type="submit" className="primary">
              Continue
            </button>
          </form>
        )}

        {state.kind === 'ready' && (
          <>
            <p>
              <strong>{state.request.botName}</strong> is asking to sign in to Estiva apps as you
              {state.request.label ? ` from “${state.request.label}”` : ''}.
            </p>
            <ul>
              <li>
                It can read and post as you in Peek and Ship for {state.request.sessionHours} hours.
              </li>
              <li>
                Everything it posts is tagged <code>{state.request.clientId}-as-…</code>, and each
                action is recorded in your account history.
              </li>
              <li>
                It cannot change your account, your passkeys or anything in the admin console.
              </li>
              <li>You can revoke it at any time from your account page.</li>
            </ul>
            <p className="card-note">
              Only {state.request.ownerDisplayName ?? 'the person this bot belongs to'} can approve
              this, with their passkey. Code {state.request.userCode}.
            </p>
            {error && <p className="notice error">{error}</p>}
            <div className="row">
              <button
                type="button"
                className="primary"
                disabled={busy}
                onClick={() => void approve(state.request)}
              >
                Approve with passkey
              </button>
              <button type="button" disabled={busy} onClick={() => void deny(state.request)}>
                Don’t allow
              </button>
            </div>
          </>
        )}

        {state.kind === 'approved' && (
          <p>
            Approved. {state.botName} can now sign in as you. You can close this page, and revoke
            access from <a href="/">your account</a> whenever you like.
          </p>
        )}

        {state.kind === 'denied' && <p>Denied. The bot’s request has been stopped.</p>}
      </section>
    </main>
  )
}
