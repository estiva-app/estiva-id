/**
 * The published half of the account page.
 *
 * Everything in this card ends up in a `kind:0` on the relay, readable by
 * anyone. The card says so, because the distinction between this and the
 * private card is the thing a person most needs to understand here and the
 * least likely to guess.
 */
import { type FormEvent, useState } from 'react'
import { ApiError, type Profile, type SaveProfileResult, saveProfile } from './api'

interface Props {
  profile: Profile
  onSaved: (profile: Profile) => void
}

type Status =
  | { kind: 'idle' }
  | { kind: 'saving' }
  | { kind: 'saved'; published: boolean; publishError?: string | null }
  | { kind: 'error'; message: string }

export function ProfileCard({ profile, onSaved }: Props) {
  const [displayName, setDisplayName] = useState(profile.displayName ?? '')
  const [picture, setPicture] = useState(profile.picture ?? '')
  const [handle, setHandle] = useState(profile.handle ?? '')
  const [handleError, setHandleError] = useState<string | undefined>()
  const [status, setStatus] = useState<Status>({ kind: 'idle' })

  const host = profile.communityHost
  const preview = handle && host ? `${handle.trim().toLowerCase()}@${host}` : null

  async function onSubmit(event: FormEvent) {
    event.preventDefault()
    setStatus({ kind: 'saving' })
    setHandleError(undefined)

    try {
      // Empty means "clear it", which the API spells as an explicit null. An
      // omitted key would mean "leave alone" and the field would never clear.
      const result: SaveProfileResult = await saveProfile({
        displayName: displayName.trim() || null,
        picture: picture.trim() || null,
        handle: handle.trim() || null,
      })
      onSaved(result.profile)
      setStatus({
        kind: 'saved',
        published: result.published,
        publishError: result.publishError,
      })
    } catch (error) {
      if (error instanceof ApiError && error.code === 'conflict') {
        setHandleError('Taken. Handles are unique within a workspace.')
        setStatus({ kind: 'idle' })
        return
      }
      if (
        error instanceof ApiError &&
        error.code === 'bad_request' &&
        'handle' in (error.detail ?? {})
      ) {
        setHandleError(error.message)
        setStatus({ kind: 'idle' })
        return
      }
      setStatus({
        kind: 'error',
        message: error instanceof Error ? error.message : 'Could not save',
      })
    }
  }

  return (
    <section className="card is-published">
      <div className="card-head">
        <h2>Your public profile</h2>
        <span className="badge published">Published</span>
      </div>
      <p className="card-note">
        These three fields are published to the relay as a signed profile event, and any app in the
        suite can read them. Changing one here changes how you appear everywhere.
      </p>

      <form onSubmit={onSubmit}>
        <label>
          <span className="label-text">Display name</span>
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            placeholder="Ada Lovelace"
            autoComplete="name"
          />
        </label>

        <label>
          <span className="label-text">Avatar URL</span>
          <input
            type="url"
            value={picture}
            onChange={(e) => setPicture(e.target.value)}
            placeholder="https://…"
          />
        </label>

        <label>
          <span className="label-text">Handle</span>
          <input
            type="text"
            value={handle}
            onChange={(e) => setHandle(e.target.value)}
            placeholder="ada"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={handleError !== undefined}
          />
          {handleError ? (
            <p className="hint error">{handleError}</p>
          ) : preview ? (
            <p className="hint">
              Others can find you as <span className="mono">{preview}</span>. Clearing this
              withdraws the handle.
            </p>
          ) : host ? (
            <p className="hint">
              Optional. With one, you are findable as <span className="mono">name@{host}</span>.
            </p>
          ) : (
            <p className="hint">
              No workspace host is configured, so a handle cannot be assigned yet.
            </p>
          )}
        </label>

        <div className="row">
          <button type="submit" className="primary" disabled={status.kind === 'saving'}>
            {status.kind === 'saving' ? 'Saving…' : 'Save and publish'}
          </button>
          <SaveStatus status={status} />
        </div>
      </form>
    </section>
  )
}

/**
 * A save can succeed while publishing fails, and that state has to be visible.
 * Postgres is the record and the relay is a projection of it, so an outage
 * keeps the edit and leaves the projection stale — reporting a plain "Saved"
 * would make a stale profile invisible, which is the failure this whole
 * feature exists to avoid.
 */
function SaveStatus({ status }: { status: Status }) {
  if (status.kind === 'error') return <span className="hint error">{status.message}</span>
  if (status.kind !== 'saved') return null

  if (status.published) return <span className="hint">Saved and published.</span>
  return (
    <span className="hint error">
      Saved here, but not published{status.publishError ? ` (${status.publishError})` : ''}. Other
      apps still show your previous profile.
    </span>
  )
}
