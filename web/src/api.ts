/**
 * The one place that talks to the service.
 *
 * Every route here answers errors in a single envelope with a stable machine
 * `code` (see `docs/API.md`), so unwrapping it once means the UI can branch on
 * `code` and `detail.reason` rather than on message strings.
 */
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/browser'

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
  /** What they may do while active — a different axis from `status`. */
  role: 'admin' | 'member'
  pubkey: string | null
}

export const getMe = () => request<Me>('/me')

// --- The directory (PEEK-64) -------------------------------------------------

/**
 * What is known about someone's standing at the relay.
 *
 * `unknown` is an answer, not a missing value. Buzz exposes no way to read
 * membership, so it is the only honest one today — and rendering it as anything
 * softer is what would make a half-offboarded person look fine.
 */
export type AdmissionStatus = 'admitted' | 'not-admitted' | 'unknown'

/** How far through setup somebody is. See `src/domain/directory.ts`. */
export type Enrolment = 'invited' | 'enrolling' | 'enrolled'

export interface Person {
  kind: 'user' | 'invite'
  id: string
  email: string | null
  displayName: string | null
  handle: string | null
  nip05: string | null
  pubkey: string | null
  role: 'admin' | 'member'
  status: 'active' | 'suspended' | 'offboarded' | null
  enrolment: Enrolment
  passkeyCount: number
  lastSeenAt: string | null
  createdAt: string
  admission: AdmissionStatus
  expiresAt: string | null
}

export const listPeople = () => request<{ people: Person[] }>('/admin/people').then((r) => r.people)

export const getPerson = (id: string) =>
  request<{ person: Person; credentials: Credential[] }>(`/admin/people/${encodeURIComponent(id)}`)

export interface OffboardResult {
  userId: string
  pubkey: string | null
  passkeysRevoked: number
  sessionsRevoked: number
  handleRevoked: string | null
  /** False means the handle still resolves for anyone reading the old event. */
  attestationPublished: boolean
  publishError?: string | null
  /**
   * Always outstanding. Buzz owns admission and exposes no way to drive it, so
   * this carries the command an operator still has to run.
   */
  relayAdmission: { revoked: false; reason: string; command: string }
}

export const offboardPerson = (id: string) =>
  request<OffboardResult>(`/admin/people/${encodeURIComponent(id)}/offboard`, { method: 'POST' })

// --- The audit trail (PEEK-69) ----------------------------------------------

export interface AuditEntry {
  id: string
  occurredAt: string
  actorType: 'user' | 'app' | 'system'
  actorUserId: string | null
  actorEmail: string | null
  actorDisplayName: string | null
  actorClientId: string | null
  action: string
  outcome: 'success' | 'refused' | 'error'
  subjectPubkey: string | null
  subjectUserId: string | null
  subjectEmail: string | null
  subjectDisplayName: string | null
  detail: Record<string, unknown>
}

export interface AuditPage {
  entries: AuditEntry[]
  /** Pass as `before` for the next page; null at the end. */
  nextBefore: string | null
  /** Distinct actions present, so the filter offers real values. */
  actions: string[]
}

export const listAudit = (filter: { person?: string; action?: string; before?: string } = {}) => {
  const params = new URLSearchParams()
  if (filter.person) params.set('person', filter.person)
  if (filter.action) params.set('action', filter.action)
  if (filter.before) params.set('before', filter.before)
  const query = params.toString()
  return request<AuditPage>(`/admin/audit${query ? `?${query}` : ''}`)
}

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

export interface UploadAvatarResult extends SaveProfileResult {
  avatar: { url: string; sha256: string; size: number }
}

/**
 * Upload an avatar to the workspace's media store (PEEK-32).
 *
 * Raw bytes with the file's own `Content-Type`, not multipart — there is one
 * file and no other fields, so `body: file` is the whole request. The service
 * signs the Blossom authorization with the custodied key, which is why this
 * cannot be a direct browser-to-relay upload.
 */
// A `Blob` rather than a `File`: what reaches here has been re-encoded to strip
// metadata (PEEK-96), so it is no longer the object the person picked.
export const uploadAvatar = (file: Blob) =>
  request<UploadAvatarResult>('/me/avatar', {
    method: 'PUT',
    // `File` is a `Blob`, so the browser sets Content-Length itself.
    body: file,
    headers: { 'content-type': file.type },
  })

// --- Getting in ---------------------------------------------------------------

export const loginOptions = () =>
  request<PublicKeyCredentialRequestOptionsJSON>('/auth/login/options', { method: 'POST' })

export const loginVerify = (assertion: unknown) =>
  request<{ verified: boolean; pubkey: string }>('/auth/login/verify', {
    method: 'POST',
    body: JSON.stringify(assertion),
  })

export interface InvitePreview {
  email: string
  displayName: string | null
  handle: string | null
}

/**
 * What an invite says, for somebody who has no session yet.
 *
 * `404` for unknown, expired and consumed alike — the reason is in the body,
 * so the screen can say which without the endpoint letting anyone probe.
 */
export async function getInvite(
  token: string,
): Promise<{ valid: true; invite: InvitePreview } | { valid: false; reason: string }> {
  const response = await fetch(`/invites/${encodeURIComponent(token)}`, {
    credentials: 'same-origin',
  })
  const body = (await response.json()) as
    | { valid: true; email: string; displayName: string | null; handle: string | null }
    | { valid: false; reason: string }

  if (!body.valid) return { valid: false, reason: body.reason }
  return {
    valid: true,
    invite: { email: body.email, displayName: body.displayName, handle: body.handle },
  }
}

/** Enrolment takes the invite, not an email — the invite carries the address. */
export const registerOptions = (inviteToken: string) =>
  request<PublicKeyCredentialCreationOptionsJSON>('/auth/register/options', {
    method: 'POST',
    body: JSON.stringify({ inviteToken }),
  })

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
export type { PublicKeyCredentialCreationOptionsJSON, PublicKeyCredentialRequestOptionsJSON }
