/**
 * Bots signed in as you, and the button that stops them (PER-22).
 *
 * Revoking takes effect on the bot's next request — `/sign` re-checks the
 * delegation every time — so this is the whole of "revocable from Estiva ID".
 * Shows nothing at all when there is nothing to revoke, which is the usual case.
 */
import { useCallback, useEffect, useState } from 'react'
import { type Delegation, listDelegations, revokeDelegation } from './api'

const formatWhen = (iso: string) =>
  new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })

export function DelegationsCard() {
  const [delegations, setDelegations] = useState<Delegation[]>([])
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setDelegations(await listDelegations())
    } catch {
      // Fails soft, like the bots list: the rest of the account page matters more.
      setDelegations([])
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  const revoke = async (id: string) => {
    setError(null)
    try {
      await revokeDelegation(id)
      await load()
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Could not revoke')
    }
  }

  if (delegations.length === 0) return null

  return (
    <section className="card">
      <div className="card-head">
        <h2>Bots signed in as you</h2>
      </div>
      <p className="card-note">
        These can read and post as you until they expire. Everything they post is tagged with the
        bot's name.
      </p>
      {error && <p className="notice error">{error}</p>}
      <ul className="plain">
        {delegations.map((delegation) => (
          <li key={delegation.id} className="row">
            <div>
              <strong>{delegation.botName}</strong>
              <div className="card-note">
                Approved {formatWhen(delegation.createdAt)} · ends{' '}
                {formatWhen(delegation.expiresAt)}
                {delegation.lastSeenAt ? ` · last used ${formatWhen(delegation.lastSeenAt)}` : ''}
              </div>
            </div>
            <button type="button" onClick={() => void revoke(delegation.id)}>
              Revoke
            </button>
          </li>
        ))}
      </ul>
    </section>
  )
}
