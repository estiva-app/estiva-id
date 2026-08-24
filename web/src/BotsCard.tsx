import { useState } from 'react'
import { ApiError, type OwnBot, createOwnBot, retireOwnBot } from './api'

/**
 * The bots you made for yourself (PEEK-164).
 *
 * **No admin anywhere in this card.** That is the point of it: onboarding one
 * more person to the Claude agent needed an admin for three separate steps, and
 * PEEK-163 existed only to make one of them possible at all. A person who can
 * sign in can make their own and start using it.
 *
 * What keeps that from being an escalation is enforced on the server, and this
 * card says so rather than leaving somebody to find out:
 *
 *  - it can **read** and cannot publish, and only an admin can widen that;
 *  - its name is composed, so it cannot claim to be somebody it is not;
 *  - it stops working when you do, because it is yours rather than the
 *    workspace's.
 *
 * Sits on your own account page rather than the admin one, next to the passkeys
 * — both are answers to "what can act as me", and a bot is the one that keeps
 * acting while you are asleep.
 *
 * Takes its list as a prop, the way `PasskeysCard` does, so every state here is
 * real data rather than a stubbed request — including the one that matters most
 * and is hardest to reach on purpose: a secret that exists for one render.
 */
export function BotsCard({
  bots,
  limit,
  onChange,
}: {
  bots: OwnBot[]
  limit: number
  onChange: (next: OwnBot[]) => void
}) {
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  /** Which bot is mid-retire, so the row can say so and not be clicked twice. */
  const [retiring, setRetiring] = useState<string | null>(null)
  /**
   * Which bot is one click from being stopped.
   *
   * A confirm step rather than an immediate action, because this cannot be
   * undone: there is no un-retire, and the bot's secret is unrecoverable, so a
   * mis-click costs setting the tool up again from scratch.
   */
  const [confirming, setConfirming] = useState<string | null>(null)
  /**
   * The one that was just made, held only in this component's state.
   *
   * Deliberately not stored anywhere: the secret is shown once and only its
   * hash is kept, so a reload losing it is the correct behaviour rather than a
   * bug. Keeping it would mean a secret sitting in browser storage, which is
   * the thing the server refuses to do.
   */
  const [issued, setIssued] = useState<{
    displayName: string
    clientId: string
    clientSecret: string
    admitted: boolean
    admissionError?: string | null
  } | null>(null)

  async function make(event: React.FormEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setCopied(false)
    try {
      const created = await createOwnBot(label.trim())
      setIssued({
        displayName: created.bot.displayName,
        clientId: created.clientId,
        clientSecret: created.clientSecret,
        admitted: created.admitted,
        admissionError: created.admissionError,
      })
      setLabel('')
      /*
        Appended from what the server returned rather than re-fetched. The list
        is the only part of this response that is safe to keep, and a round trip
        would be a second chance for the secret on screen to be lost to a
        re-render.
      */
      onChange([...bots, { id: created.bot.userId, displayName: created.bot.displayName }])
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not make that bot.')
    } finally {
      setBusy(false)
    }
  }

  async function retire(bot: OwnBot) {
    setRetiring(bot.id)
    setError(null)
    try {
      await retireOwnBot(bot.id)
      onChange(bots.filter((candidate) => candidate.id !== bot.id))
      setConfirming(null)
    } catch (caught) {
      setError(caught instanceof ApiError ? caught.message : 'Could not stop that bot.')
    } finally {
      setRetiring(null)
    }
  }

  const atLimit = bots.length >= limit && limit > 0

  return (
    <section className="card">
      <div className="card-head">
        <h2>Your bots</h2>
      </div>
      <p className="card-note">
        A bot reads this workspace as you, from a tool like Claude Desktop. It{' '}
        <strong>cannot write anything</strong> — ask an admin if you need one that can — and it{' '}
        <strong>stops working when your account does</strong>, so it is not something that outlives
        you here.
      </p>

      {issued ? (
        <>
          {/*
            The whole reason this card exists in this shape. The secret is
            shown once and only its hash is stored, so there is no screen
            anywhere that can show it again — and somebody who navigates away
            has to make another bot rather than look it up.
          */}
          <div className="notice">
            <strong>Copy the secret now.</strong> Only its hash is stored, so it cannot be shown
            again — if you lose it, make another bot and stop this one.
          </div>
          <dl className="facts">
            <dt>Name</dt>
            <dd>{issued.displayName}</dd>
            <dt>Client id</dt>
            <dd className="mono">{issued.clientId}</dd>
            <dt>Secret</dt>
            <dd className="mono">{issued.clientSecret}</dd>
          </dl>
          {/*
            Reported rather than hidden. A bot whose key never reached the relay
            authenticates fine and then reads nothing, which surfaces as
            `relay_membership_required` — a message that reads like a permission
            bug and is actually a missing member.
          */}
          {!issued.admitted && (
            <div className="notice warn">
              Made, but its key did not reach the relay
              {issued.admissionError ? ` (${issued.admissionError})` : ''}. It will authenticate and
              read nothing until an admin admits it.
            </div>
          )}
          <div className="row">
            <button
              type="button"
              onClick={() => {
                void navigator.clipboard.writeText(issued.clientSecret).then(() => setCopied(true))
              }}
            >
              {copied ? 'Copied' : 'Copy secret'}
            </button>
            <button type="button" className="link" onClick={() => setIssued(null)}>
              Done
            </button>
          </div>
        </>
      ) : (
        <>
          {error && <div className="notice error">{error}</div>}

          {bots.length > 0 && (
            <ul className="plain">
              {bots.map((bot) => (
                <li key={bot.id} className="row">
                  <span>{bot.displayName ?? bot.id}</span>
                  {confirming === bot.id ? (
                    <>
                      {/*
                        Says what stopping actually does before it is done.
                        PEEK-170 was a Delete that left every message readable;
                        the lesson is to name the outcome you produce, so this
                        one says plainly which half it cannot undo.
                      */}
                      <span className="card-note">
                        It stops working immediately and cannot be restarted. Anything it already
                        wrote stays.
                      </span>
                      <button
                        type="button"
                        onClick={() => {
                          void retire(bot)
                        }}
                        disabled={retiring === bot.id}
                      >
                        {retiring === bot.id ? 'Stopping…' : 'Stop it'}
                      </button>
                      <button type="button" className="link" onClick={() => setConfirming(null)}>
                        Keep it
                      </button>
                    </>
                  ) : (
                    <button type="button" className="link" onClick={() => setConfirming(bot.id)}>
                      Stop
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}

          {atLimit ? (
            <div className="notice">
              You have {limit} bots, which is the most one person can have. Stop one before making
              another.
            </div>
          ) : (
            <form onSubmit={make}>
              <label>
                <span className="label-text">What is it for?</span>
                <input
                  value={label}
                  onChange={(event) => setLabel(event.target.value)}
                  placeholder="Laptop"
                  maxLength={80}
                  disabled={busy}
                />
              </label>
              {/*
                Said before they type, not after. The name is composed from this
                and their own, so somebody expecting "Laptop" to be the whole
                name should find that out here rather than in a chat.
              */}
              <p className="card-note">
                Its full name will say it is steered by you, so anyone reading a message from it
                knows who is behind it.
              </p>
              <button type="submit" disabled={busy || label.trim() === ''}>
                {busy ? 'Making…' : 'Make a bot'}
              </button>
            </form>
          )}
        </>
      )}
    </section>
  )
}
