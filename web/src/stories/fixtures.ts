/**
 * Fixture data for the account UI's stories.
 *
 * One place, so a person appears with the same name and pubkey wherever they
 * turn up. The people are the ones this workspace actually has, because a
 * screen full of "User One" hides the thing these screens are for: names and
 * handles of wildly different lengths, and accounts in states nobody would
 * invent on purpose.
 */
import type { AuditEntry, Credential, Me, Person, Profile, SecurityEvent } from '../api'

/** Stable, obviously-fake keys. 64 hex, because everything downstream assumes it. */
export const PUBKEY = {
  cath: 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90',
  jan: '0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0',
  ravi: 'bb00cc11dd22ee33ff44aa55bb66cc77dd88ee99ff00aa11bb22cc33dd44ee55',
} as const

export const me: Me = {
  id: 'usr_01HQ8ZK3',
  email: 'katerina@estiva.app',
  displayName: 'Katerina',
  status: 'active',
  role: 'admin',
  pubkey: PUBKEY.cath,
}

export const profile: Profile = {
  displayName: 'Katerina',
  picture: null,
  handle: 'cath',
  communityHost: 'estiva.estiva.app',
  nip05: 'cath@estiva.estiva.app',
  pubkey: PUBKEY.cath,
}

/**
 * A profile that has been claimed but never filled in.
 *
 * The state every account passes through between enrolling and the first save,
 * and the one where the empty-field styling either holds up or does not.
 */
export const emptyProfile: Profile = {
  displayName: null,
  picture: null,
  handle: null,
  communityHost: 'estiva.estiva.app',
  nip05: null,
  pubkey: PUBKEY.cath,
}

/**
 * A picture that renders without a network.
 *
 * `ProfileCard` shows the picture *and* prints its URL, so a story cannot use a
 * real relay link: the image would 404 in Storybook and the filled state - the
 * one worth designing - would show an empty box.
 *
 * A single-pixel PNG, scaled by `object-fit: cover`. Deliberately not an inline
 * SVG: percent-encoded markup ran to three wrapped lines and the hint became
 * the loudest thing on the card. At 114 characters this sits where a real
 * checksum URL sits, so the line wraps the way it does in the app.
 */
export const PICTURE =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAIAAACQd1PeAAAADElEQVR42mNYfOccAARzAk5FO2zKAAAAAElFTkSuQmCC'

export const profileWithPicture: Profile = { ...profile, picture: PICTURE }

const days = (n: number) => new Date(Date.UTC(2026, 7, 18, 9, 30) - n * 86_400_000).toISOString()

/** A platform passkey — the common case, synced and backed up. */
export const platformCredential: Credential = {
  id: 'cred_windows_hello',
  nickname: 'Windows Hello',
  deviceType: 'multiDevice',
  backedUp: true,
  transports: ['internal', 'hybrid'],
  createdAt: days(40),
  lastUsedAt: days(0),
}

/** A hardware key: single-device, not backed up, and never nicknamed. */
export const securityKeyCredential: Credential = {
  id: 'cred_yubikey',
  nickname: null,
  deviceType: 'singleDevice',
  backedUp: false,
  transports: ['usb', 'nfc'],
  createdAt: days(12),
  lastUsedAt: null,
}

export const phoneCredential: Credential = {
  id: 'cred_phone',
  nickname: 'iPhone',
  deviceType: 'multiDevice',
  backedUp: true,
  transports: ['hybrid'],
  createdAt: days(3),
  lastUsedAt: days(1),
}

export const credentials: Credential[] = [
  platformCredential,
  phoneCredential,
  securityKeyCredential,
]

/**
 * `bySomeoneElse` is the whole point of the security card, so the fixtures
 * include an admin-issued recovery — the line this screen exists to surface.
 */
export const securityEvents: SecurityEvent[] = [
  {
    id: 'sec_1',
    occurredAt: days(0),
    action: 'session.create',
    outcome: 'success',
    actorEmail: 'katerina@estiva.app',
    actorDisplayName: 'Katerina',
    bySomeoneElse: false,
  },
  {
    id: 'sec_2',
    occurredAt: days(1),
    action: 'passkey.register',
    outcome: 'success',
    actorEmail: 'katerina@estiva.app',
    actorDisplayName: 'Katerina',
    bySomeoneElse: false,
  },
  {
    id: 'sec_3',
    occurredAt: days(6),
    action: 'recovery.issue',
    outcome: 'success',
    actorEmail: 'jan@estiva.app',
    actorDisplayName: 'Jan Mikula',
    bySomeoneElse: true,
  },
  {
    id: 'sec_4',
    occurredAt: days(6),
    action: 'recovery.complete',
    outcome: 'success',
    actorEmail: 'katerina@estiva.app',
    actorDisplayName: 'Katerina',
    bySomeoneElse: false,
  },
  {
    id: 'sec_5',
    occurredAt: days(20),
    action: 'passkey.revoke',
    outcome: 'success',
    actorEmail: 'katerina@estiva.app',
    actorDisplayName: 'Katerina',
    bySomeoneElse: false,
  },
]

const auditEntry = (over: Partial<AuditEntry> & Pick<AuditEntry, 'id' | 'action'>): AuditEntry => ({
  occurredAt: days(0),
  actorType: 'user',
  actorUserId: 'usr_01HQ8ZK3',
  actorEmail: 'katerina@estiva.app',
  actorDisplayName: 'Katerina',
  actorClientId: null,
  outcome: 'success',
  subjectPubkey: null,
  subjectUserId: null,
  subjectEmail: null,
  subjectDisplayName: null,
  detail: {},
  ...over,
})

/** All three actor types and all three outcomes, because they are styled apart. */
export const auditEntries: AuditEntry[] = [
  auditEntry({ id: 'aud_1', action: 'session.create' }),
  auditEntry({
    id: 'aud_2',
    action: 'authorize.issue',
    actorType: 'app',
    actorUserId: null,
    actorEmail: null,
    actorDisplayName: null,
    actorClientId: 'estiva-peek',
  }),
  auditEntry({
    id: 'aud_3',
    action: 'authorize.probe',
    actorType: 'app',
    actorUserId: null,
    actorEmail: null,
    actorDisplayName: null,
    actorClientId: 'estiva-ship',
    outcome: 'refused',
    detail: { reason: 'login_required' },
  }),
  auditEntry({
    id: 'aud_4',
    action: 'invite.create',
    occurredAt: days(2),
    subjectEmail: 'ravi@estiva.app',
    subjectDisplayName: 'Ravi Chandra',
  }),
  auditEntry({
    id: 'aud_5',
    action: 'user.offboard',
    occurredAt: days(9),
    outcome: 'error',
    subjectEmail: 'former@estiva.app',
    subjectDisplayName: 'Former Colleague',
    detail: { reason: 'relay_unreachable' },
  }),
  auditEntry({
    id: 'aud_6',
    action: 'profile.publish',
    occurredAt: days(11),
    actorType: 'system',
    actorUserId: null,
    actorEmail: null,
    actorDisplayName: null,
    subjectPubkey: PUBKEY.jan,
  }),
]

export const AUDIT_ACTIONS = [
  'session.create',
  'authorize.issue',
  'authorize.probe',
  'invite.create',
  'user.offboard',
  'profile.publish',
]

// --- The admin console -------------------------------------------------------

const person = (over: Partial<Person> & Pick<Person, 'id' | 'kind'>): Person => ({
  email: null,
  displayName: null,
  handle: null,
  nip05: null,
  pubkey: null,
  role: 'member',
  status: 'active',
  enrolment: 'enrolled',
  passkeyCount: 1,
  lastSeenAt: days(0),
  createdAt: days(60),
  admission: 'admitted',
  isOperator: false,
  expiresAt: null,
  ...over,
})

/**
 * One row per thing that is styled differently, rather than a plausible team.
 *
 * The admin console exists to show who is half set up, so a list of healthy
 * accounts would demonstrate nothing. Every awkward combination the directory
 * can produce is here: an invite nobody accepted, somebody enrolling with no
 * passkey yet, a member the relay has not admitted, a suspended account, an
 * offboarded one, and the operator identity whose offboarding would disable
 * admission for everybody.
 */
export const people: Person[] = [
  person({
    id: 'usr_01HQ8ZK3',
    kind: 'user',
    email: 'katerina@estiva.app',
    displayName: 'Katerina',
    handle: 'cath',
    nip05: 'cath@estiva.estiva.app',
    pubkey: PUBKEY.cath,
    role: 'admin',
    passkeyCount: 3,
  }),
  person({
    id: 'usr_01HQ8ZK4',
    kind: 'user',
    email: 'jan@estiva.app',
    displayName: 'Jan Mikula',
    handle: 'jan',
    nip05: 'jan@estiva.estiva.app',
    pubkey: PUBKEY.jan,
    role: 'admin',
    passkeyCount: 2,
    lastSeenAt: days(1),
  }),
  /** Enrolled, but the relay has not let them in — they can sign in and see nothing. */
  person({
    id: 'usr_01HQ8ZK5',
    kind: 'user',
    email: 'ravi@estiva.app',
    displayName: 'Ravi Chandra',
    handle: 'ravi',
    nip05: 'ravi@estiva.estiva.app',
    pubkey: PUBKEY.ravi,
    admission: 'not-admitted',
    lastSeenAt: days(4),
  }),
  /** Accepted the invite, no passkey yet: stuck mid-ceremony. */
  person({
    id: 'usr_01HQ8ZK6',
    kind: 'user',
    email: 'ana@estiva.app',
    displayName: 'Ana Ferreira',
    enrolment: 'enrolling',
    passkeyCount: 0,
    admission: 'not-admitted',
    lastSeenAt: null,
    createdAt: days(2),
  }),
  /** Invited and never seen. Expires, which is why the date is on the row. */
  person({
    id: 'inv_01HQ8ZL1',
    kind: 'invite',
    email: 'newcomer@estiva.app',
    status: null,
    enrolment: 'invited',
    passkeyCount: 0,
    admission: 'not-admitted',
    lastSeenAt: null,
    createdAt: days(1),
    expiresAt: days(-6),
  }),
  /** An invite past its 168 hours — present, and no longer usable. */
  person({
    id: 'inv_01HQ8ZL2',
    kind: 'invite',
    email: 'stale@estiva.app',
    status: null,
    enrolment: 'invited',
    passkeyCount: 0,
    admission: 'not-admitted',
    lastSeenAt: null,
    createdAt: days(30),
    expiresAt: days(23),
  }),
  person({
    id: 'usr_01HQ8ZK7',
    kind: 'user',
    email: 'suspended@estiva.app',
    displayName: 'Suspended Person',
    handle: 'suspended',
    pubkey: PUBKEY.ravi,
    status: 'suspended',
    admission: 'not-admitted',
    lastSeenAt: days(30),
  }),
  person({
    id: 'usr_01HQ8ZK8',
    kind: 'user',
    email: 'former@estiva.app',
    displayName: 'Former Colleague',
    status: 'offboarded',
    passkeyCount: 0,
    admission: 'not-admitted',
    lastSeenAt: days(90),
  }),
  /** A key with no way to sign in — and the one that gates everyone's admission. */
  person({
    id: 'rol_01HQ8ZM1',
    kind: 'role',
    displayName: 'Relay operator',
    pubkey: PUBKEY.jan,
    enrolment: 'not-applicable',
    passkeyCount: 0,
    lastSeenAt: null,
    isOperator: true,
  }),
  person({
    id: 'rol_01HQ8ZM2',
    kind: 'role',
    displayName: 'Peek backend',
    pubkey: PUBKEY.cath,
    enrolment: 'not-applicable',
    passkeyCount: 0,
    lastSeenAt: null,
  }),
]

/** Admission could not be read at all, so every chip in the list is stale. */
export const peopleAdmissionUnknown: Person[] = people.map((p) => ({ ...p, admission: 'unknown' }))
