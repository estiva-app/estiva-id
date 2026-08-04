-- Estiva ID — initial schema.
--
-- Design notes that are decisions, not incidental:
--
--   * Nothing that can sign is stored in plaintext. Both the per-user Nostr
--     secret and the JWT private key live in an encryption envelope whose
--     key-encryption key comes from the environment. A database dump alone
--     therefore yields neither signatures nor forged tokens (PEEK-27).
--   * Session tokens are stored as hashes for the same reason.
--   * Credentials, keys and sessions are revoked by timestamp rather than
--     deleted. Offboarding needs to be auditable after the fact, and audit rows
--     that reference vanished ids are worth little.

-- ---------------------------------------------------------------------------
-- People
-- ---------------------------------------------------------------------------

create table users (
  id            uuid primary key default gen_random_uuid(),

  -- Email is a *private* directory attribute. It is never published to a relay
  -- and never appears in a kind:0 event — that split is the point of having a
  -- private directory alongside the public profile.
  email         text unique,
  display_name  text,

  status        text not null default 'active'
                check (status in ('active', 'suspended', 'offboarded')),

  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Passkeys (PEEK-26)
--
-- The passkey is an *authenticator* only. It does not wrap the Nostr key —
-- that is Stage 4 (passkey-PRF), and keeping the two apart is what lets Stage 1
-- ship without forcing client-side signing.
-- ---------------------------------------------------------------------------

create table webauthn_credentials (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references users(id) on delete cascade,

  credential_id  bytea not null unique,
  public_key     bytea not null,

  -- Cloned-authenticator detection. A counter that goes backwards means the
  -- credential has been copied.
  sign_count     bigint not null default 0,

  transports     text[] not null default '{}',
  aaguid         text,
  backed_up      boolean not null default false,
  device_type    text,

  -- User-supplied label, so "revoke the lost laptop" is a decidable action.
  nickname       text,

  created_at     timestamptz not null default now(),
  last_used_at   timestamptz,
  revoked_at     timestamptz
);

-- Multiple credentials per user from day one: a lost laptop should be an
-- inconvenience, not an identity loss.
create index webauthn_credentials_active_idx
  on webauthn_credentials (user_id)
  where revoked_at is null;

-- Ceremony challenges. Single-use and short-lived: replaying a challenge is the
-- whole attack WebAuthn's nonce exists to prevent.
create table webauthn_challenges (
  id          uuid primary key default gen_random_uuid(),
  challenge   text not null unique,
  ceremony    text not null check (ceremony in ('registration', 'authentication')),

  -- Null for a discoverable-credential login, where the user is not yet known.
  user_id     uuid references users(id) on delete cascade,

  created_at  timestamptz not null default now(),
  expires_at  timestamptz not null,
  consumed_at timestamptz
);

create index webauthn_challenges_expiry_idx on webauthn_challenges (expires_at);

-- ---------------------------------------------------------------------------
-- Custodied Nostr keys (PEEK-27)
-- ---------------------------------------------------------------------------

create table user_keys (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references users(id) on delete cascade,

  -- x-only schnorr public key, 64 lowercase hex characters. This is the value
  -- that appears as `sub` in issued JWTs and as `pubkey` on signed events.
  pubkey      text not null unique check (pubkey ~ '^[0-9a-f]{64}$'),

  -- The encryption envelope. Shape is owned by src/crypto/envelope.ts and is
  -- versioned so Stage 4 can add M-of-N escrow wraps without re-encrypting a
  -- single secret. See docs/KEY-CUSTODY.md.
  envelope    jsonb not null,

  status      text not null default 'active'
              check (status in ('active', 'rotated', 'revoked')),

  created_at  timestamptz not null default now(),
  rotated_at  timestamptz
);

-- Exactly one signable key per user. Superseded rows are kept: Stage 2 migrates
-- Estiva Peek's existing custodied keys in, and relay history signed under an
-- old pubkey still has to be attributable.
create unique index user_keys_one_active_idx
  on user_keys (user_id)
  where status = 'active';

-- ---------------------------------------------------------------------------
-- App credentials and signing policy (PEEK-71)
-- ---------------------------------------------------------------------------

create table app_credentials (
  id                 uuid primary key default gen_random_uuid(),

  -- Also the JWT `aud`. A token issued for one app cannot be replayed against
  -- another app's policy, because the audience selects the policy row.
  client_id          text not null unique,
  name               text not null,

  -- Kinds this app may ask /sign for. Empty means this app may sign nothing.
  -- kind:0 is refused for every app regardless of what is listed here — the
  -- identity service owns profiles, and an app that can publish one can undo
  -- that ownership.
  allowed_kinds      integer[] not null default '{}',

  -- URL prefixes this app may mint NIP-98 (kind 27235) events for. Empty means
  -- none. Narrows, and never widens, the deployment-wide allowlist in config.
  nip98_url_prefixes text[] not null default '{}',

  status             text not null default 'active'
                     check (status in ('active', 'disabled')),

  created_at         timestamptz not null default now(),
  updated_at         timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

create table sessions (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references users(id) on delete cascade,

  -- SHA-256 of the opaque cookie value. The cookie itself is never stored, so a
  -- dump does not hand over live sessions.
  token_hash    bytea not null unique,

  -- Which passkey opened this session, for the audit trail.
  credential_id uuid references webauthn_credentials(id) on delete set null,

  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  revoked_at    timestamptz,
  last_seen_at  timestamptz,
  user_agent    text
);

create index sessions_user_idx on sessions (user_id) where revoked_at is null;

-- ---------------------------------------------------------------------------
-- JWT signing keys (PEEK-29)
--
-- Persisted rather than generated per boot: JWKS must be stable across restarts
-- and across replicas, or relying parties see tokens signed by a `kid` that
-- discovery does not list.
-- ---------------------------------------------------------------------------

create table jwt_signing_keys (
  kid                  text primary key,
  alg                  text not null default 'ES256',

  public_jwk           jsonb not null,
  -- Same envelope scheme as user keys: a dump must not allow token forgery
  -- either.
  private_jwk_envelope jsonb not null,

  status               text not null
                       check (status in ('active', 'previous', 'retired')),

  created_at           timestamptz not null default now(),
  retired_at           timestamptz
);

-- One signing key at a time; `previous` stays served in JWKS so tokens issued
-- before a rotation keep validating until they expire.
create unique index jwt_signing_keys_one_active_idx
  on jwt_signing_keys (status)
  where status = 'active';

-- ---------------------------------------------------------------------------
-- Audit (PEEK-69)
--
-- Stage 1 custody means the service *can* sign as anyone. The argument for
-- accepting that is not that it will not happen, but that it cannot happen
-- unseen — which is why this table is here now and not later.
-- ---------------------------------------------------------------------------

create table audit_events (
  id             bigserial primary key,
  occurred_at    timestamptz not null default now(),

  actor_type     text not null check (actor_type in ('user', 'app', 'system')),
  actor_user_id  uuid references users(id) on delete set null,
  actor_client_id text,

  -- Dotted verb, e.g. 'sign.granted', 'sign.refused', 'passkey.registered'.
  action         text not null,
  outcome        text not null check (outcome in ('success', 'refused', 'error')),

  -- The pubkey acted upon, when there is one.
  subject_pubkey text,

  -- Never put key material, event content or PII in here.
  detail         jsonb not null default '{}',

  request_id     text
);

create index audit_events_time_idx on audit_events (occurred_at desc);
create index audit_events_actor_idx on audit_events (actor_user_id, occurred_at desc);
create index audit_events_action_idx on audit_events (action, occurred_at desc);
