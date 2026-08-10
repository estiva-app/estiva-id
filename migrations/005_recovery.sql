-- ---------------------------------------------------------------------------
-- Account recovery (PEEK-67)
--
-- Somebody loses every device that held a passkey. Without this they are simply
-- gone: enrolling a second passkey needs an existing session, which is exactly
-- what they cannot get. Revoking your *last* passkey is refused for the same
-- reason, and that refusal is only defensible if a way back exists.
--
-- **Their Nostr key is untouched.** Nothing here writes `user_keys`, so the
-- pubkey — and therefore everything they ever signed — stays theirs. That is
-- the thing custody actually buys, and it is why Stage 4 cannot simply drop
-- custody: passkey-PRF wrapped keys mean nobody can perform this, so escrow has
-- to exist before custody goes.
--
-- ## Why not reuse `invites`
--
-- An invite creates a person; recovery restores one. They differ in the only
-- way that matters: `/auth/register/options` refuses an invite whose email
-- already has a passkey, and that refusal is what stops an invite being used to
-- bolt a credential onto somebody else's account. Recovery must bypass exactly
-- that guard, so it gets its own table and its own route rather than a flag
-- that makes the guard conditional.
-- ---------------------------------------------------------------------------

create table recovery_tokens (
  id           uuid primary key default gen_random_uuid(),

  -- SHA-256 of the token, never the token — same reasoning as `invites`. This
  -- link is strictly more dangerous than an invite: it opens an existing
  -- identity with history behind it rather than an empty new one.
  token_hash   bytea not null unique,

  -- Who is being restored. Cascade because a recovery link for a deleted user
  -- is meaningless, not something to keep.
  user_id      uuid not null references users(id) on delete cascade,

  -- The admin who issued it. Retained on their deletion, because "who restored
  -- this account" is the question the audit trail exists to answer.
  created_by   uuid references users(id) on delete set null,

  expires_at   timestamptz not null,

  -- Single use, set when a passkey is actually enrolled — not when the link is
  -- opened. Burning it at `/options` would turn a dismissed browser prompt into
  -- a second call to the admin, and dismissing that prompt is the commonest way
  -- enrolment fails.
  consumed_at  timestamptz,

  created_at   timestamptz not null default now()
);

-- Issuing a new link supersedes any outstanding one, so this stays tiny and the
-- lookup for "is there a live link for this person" is a single row.
create index recovery_tokens_user_idx on recovery_tokens (user_id) where consumed_at is null;
create index recovery_tokens_expiry_idx on recovery_tokens (expires_at) where consumed_at is null;

-- ---------------------------------------------------------------------------
-- A ceremony of its own
--
-- A recovery challenge must not be redeemable at `/auth/register/verify`. That
-- route inserts a credential and stops — it does not retire the old passkeys or
-- burn the recovery token — so a recovery driven through it would leave a live
-- link and a lost device that still works. Distinguishing the ceremony makes
-- that combination unrepresentable rather than merely unlikely.
-- ---------------------------------------------------------------------------

alter table webauthn_challenges
  drop constraint webauthn_challenges_ceremony_check;

alter table webauthn_challenges
  add constraint webauthn_challenges_ceremony_check
  check (ceremony in ('registration', 'authentication', 'recovery'));
