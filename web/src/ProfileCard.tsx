/**
 * The published half of the account page.
 *
 * Everything in this card ends up in a `kind:0` on the relay, readable by
 * anyone. The card says so, because the distinction between this and the
 * private card is the thing a person most needs to understand here and the
 * least likely to guess.
 */
import { type FormEvent, useRef, useState } from 'react'
import { ApiError, type Profile, type SaveProfileResult, saveProfile, uploadAvatar } from './api'
import { ImageUnreadable, prepareAvatar } from './image'

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

        <AvatarField
          picture={picture}
          onUploaded={(result) => {
            setPicture(result.profile.picture ?? '')
            onSaved(result.profile)
            setStatus({
              kind: 'saved',
              published: result.published,
              publishError: result.publishError,
            })
          }}
          onCleared={() => setPicture('')}
        />

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
 * Choosing a picture (PEEK-32).
 *
 * A file picker rather than a URL box. The URL is not a thing a person has —
 * it is a sha256 of the bytes, produced by the upload — so asking for one was
 * asking them to host an image somewhere first, which is why Stage 0 ended up
 * pointing every avatar at one app's storage.
 *
 * The resulting URL is still shown. It is content-addressed and lives on the
 * workspace's own relay, and both of those are the point of the change.
 *
 * **Uploading publishes immediately**, unlike the text fields, which wait for
 * Save. It has to: the bytes are already stored and `picture` has already
 * changed, so leaving the profile unpublished would mean the relay disagreeing
 * with this page until something else happened to save.
 */
function AvatarField({
  picture,
  onUploaded,
  onCleared,
}: {
  picture: string
  onUploaded: (result: Awaited<ReturnType<typeof uploadAvatar>>) => void
  onCleared: () => void
}) {
  const input = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function onPick(file: File) {
    setBusy(true)
    setError(null)
    try {
      // Metadata is stripped before the bytes leave the browser (PEEK-96). The
      // relay refuses any image carrying EXIF, which is every photo off a phone
      // — and uploading one would publish its GPS coordinates to a shared relay.
      onUploaded(await uploadAvatar(await prepareAvatar(file)))
    } catch (caught) {
      // The one refusal worth naming: the person exists here but the relay has
      // never been told about them, and only an operator can fix it. "Upload
      // failed" would send them looking at their file.
      if (
        caught instanceof ApiError &&
        (caught.detail as { reason?: string } | undefined)?.reason === 'not_admitted'
      ) {
        setError(
          'Your identity has not been admitted to the workspace relay yet, so it cannot store files. Ask an admin.',
        )
      } else if (caught instanceof ImageUnreadable) {
        setError(caught.message)
      } else if (caught instanceof ApiError) {
        // Carry the media store's own words. Without them this said only "the
        // media store refused that file", which is not something anybody can
        // act on — and it was the message that made PEEK-96 take source-reading
        // to diagnose.
        const detail = (caught.detail as { detail?: unknown } | undefined)?.detail
        setError(
          typeof detail === 'string' && detail ? `${caught.message}: ${detail}` : caught.message,
        )
      } else {
        setError(caught instanceof Error ? caught.message : 'Could not upload that picture')
      }
    } finally {
      setBusy(false)
      // Let the same file be chosen again after a failure.
      if (input.current) input.current.value = ''
    }
  }

  return (
    <div className="field">
      <span className="label-text">Picture</span>

      <div className="row avatar-row">
        {picture ? (
          <img className="avatar-preview" src={picture} alt="" />
        ) : (
          <div className="avatar-preview is-empty" aria-hidden="true" />
        )}

        <input
          ref={input}
          type="file"
          accept="image/png,image/jpeg,image/webp,image/gif"
          hidden
          onChange={(e) => {
            const file = e.target.files?.[0]
            if (file) void onPick(file)
          }}
        />
        <button type="button" onClick={() => input.current?.click()} disabled={busy}>
          {busy ? 'Uploading…' : picture ? 'Replace' : 'Choose a picture'}
        </button>
        {picture && (
          <button type="button" className="link" onClick={onCleared} disabled={busy}>
            Remove
          </button>
        )}
      </div>

      {error ? (
        <p className="hint error">{error}</p>
      ) : picture ? (
        <p className="hint">
          Stored on the workspace relay and addressed by its own checksum, so the link stays valid
          for as long as the workspace does. <span className="mono">{picture}</span>
        </p>
      ) : (
        <p className="hint">PNG, JPEG, WebP or GIF, up to 5 MB. Removing takes effect on save.</p>
      )}
    </div>
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
