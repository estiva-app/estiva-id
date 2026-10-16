/**
 * The one line that says why a passkey sheet just appeared (AUT-2).
 *
 * Changing the account more than 15 minutes after the last tap asks for the
 * passkey first; the API client does the asking, and this shows it on
 * whichever page the change was made from.
 */
import { useEffect, useState } from 'react'
import { onConfirmStep } from './api'

export function ConfirmNotice() {
  const [asking, setAsking] = useState(false)
  useEffect(() => onConfirmStep(setAsking), [])
  if (!asking) return null
  return <output className="notice warn confirm-notice">Confirm it's you with your passkey.</output>
}
