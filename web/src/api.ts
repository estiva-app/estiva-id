/**
 * The one place that talks to the service.
 *
 * Every route here answers errors in a single envelope with a stable machine
 * `code` (see `docs/API.md`), so unwrapping it once means the UI can branch on
 * `code` and `detail.reason` rather than on message strings.
 */
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/browser'

export type ErrorCode =
  | 'bad_request'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'policy_violation'
  | 'internal'

export class ApiError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly status: number,
    readonly detail?: Record<string, unknown>,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init.body ? { 'content-type': 'application/json' } : {}),
      ...init.headers,
    },
    // The session is an httpOnly cookie on this origin. Without this a
    // same-origin fetch still sends it, but being explicit keeps the intent
    // obvious if the UI ever moves.
    credentials: 'same-origin',
  })

  const text = await response.text()
  const body: unknown = text ? JSON.parse(text) : null

  if (!response.ok) {
    const envelope = (
      body as { error?: { code?: ErrorCode; message?: string; detail?: Record<string, unknown> } }
    )?.error
    throw new ApiError(
      envelope?.code ?? 'internal',
      envelope?.message ?? `Request failed (${response.status})`,
      response.status,
      envelope?.detail,
    )
  }
  return body as T
}

// --- Identity ---------------------------------------------------------------

export interface Me {
  id: string
  email: string | null
  displayName: string | null
  status: 'active' | 'suspended' | 'offboarded'
  pubkey: string | null
}

export const getMe = () => request<Me>('/me')

// --- Profile ----------------------------------------------------------------

export interface Profile {
  displayName: string | null
  picture: string | null
  handle: string | null
  communityHost: string | null
  nip05: string | null
  pubkey: string | null
}

export interface SaveProfileResult {
  profile: Profile
  /** False when the save committed but the relay did not take it. */
  published: boolean
  eventId: string | null
  publishError?: string | null
}

export const getProfile = () => request<Profile>('/me/profile')

/**
 * An omitted field is left alone; an explicit `null` clears it.
 *
 * That distinction is the API's, not a convenience here — collapsing them would
 * make saving an avatar silently revoke the person's handle.
 */
export const saveProfile = (update: {
  displayName?: string | null
  picture?: string | null
  handle?: string | null
}) => request<SaveProfileResult>('/me/profile', { method: 'PUT', body: JSON.stringify(update) })

// --- Passkeys ---------------------------------------------------------------

export interface Credential {
  id: string
  nickname: string | null
  deviceType: string | null
  backedUp: boolean
  transports: string[]
  createdAt: string
  lastUsedAt: string | null
}

export const listCredentials = () =>
  request<{ credentials: Credential[] }>('/me/credentials').then((r) => r.credentials)

export const enrolCredentialOptions = () =>
  request<PublicKeyCredentialCreationOptionsJSON>('/auth/credentials/options', { method: 'POST' })

export const verifyCredential = (attestation: unknown) =>
  request<{ verified: boolean }>('/auth/register/verify', {
    method: 'POST',
    body: JSON.stringify(attestation),
  })

export const revokeCredential = (id: string) =>
  request<{ ok: true }>(`/me/credentials/${encodeURIComponent(id)}`, { method: 'DELETE' })

// --- Sessions ---------------------------------------------------------------

export const revokeOtherSessions = () =>
  request<{ revoked: number }>('/me/sessions/revoke-others', { method: 'POST' })

export const logout = () => request<{ ok: true }>('/auth/logout', { method: 'POST' })

/** Re-exported so callers do not each import from the WebAuthn package. */
export type { PublicKeyCredentialCreationOptionsJSON }
