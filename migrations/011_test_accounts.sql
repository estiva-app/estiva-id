-- ---------------------------------------------------------------------------
-- Test accounts that sign in with nobody present (PER-22)
--
-- QA-1 and QA-2 exist so the agent can reproduce what a person sees — read
-- state, unread dots, a second participant — without acting as a real person,
-- whose markers move when anything is opened as them.
--
-- **They are people in every way the rest of the suite can see.** `kind` stays
-- `human`, their `kind:0` carries no bot or test marker, and their messages
-- light dots like anybody's (Miky's call: "that's the point of testing"). The
-- one difference is here, and it never leaves this service: how they sign in.
--
-- A person signs in with a passkey, which needs a person. A test account signs
-- in with a secret instead, exchanged for an ordinary session. That is a
-- password, and the reason it is acceptable is that **only a test account can
-- hold one** — enforced by the schema below rather than by the one script that
-- mints them, so no later path can hand a real person a credential that skips
-- their passkey.
-- ---------------------------------------------------------------------------

alter table users
  add column test_account boolean not null default false;

-- The target of the foreign key below. `id` is already unique; this exists only
-- so a row elsewhere can reference the pair.
alter table users
  add constraint users_id_test_account_key unique (id, test_account);

-- A test account is a stand-in for a person, so it is never a bot and never an
-- admin: the first would make it something other than what it tests, the
-- second would put an unattended credential in front of the admin console.
alter table users
  add constraint users_test_account_is_a_member
  check (not test_account or (kind = 'human' and role = 'member' and owner_user_id is null));

create table test_credentials (
  user_id     uuid primary key,

  -- Always true, and referenced together with `user_id`: the composite key can
  -- only resolve to a user whose `test_account` is true. Flipping a user's flag
  -- back to false while a credential exists is refused by the same key.
  is_test     boolean not null default true check (is_test),

  -- SHA-256 of the secret, never the secret — like every other bearer here.
  secret_hash bytea not null,

  created_at  timestamptz not null default now(),
  revoked_at  timestamptz,

  foreign key (user_id, is_test) references users (id, test_account) on delete cascade
);
