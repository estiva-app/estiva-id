-- ---------------------------------------------------------------------------
-- Role and service identities (PEEK-34)
--
-- Bots, `support@`, agents. The distinction from a human is real rather than
-- cosmetic, and it is about **who the principal is**:
--
--   * For a role there is no human to hold a key. The org genuinely is the
--     principal, so custody is correct forever.
--   * For a human, custody is a temporary trade that Stage 4 unwinds by moving
--     the key behind a passkey-PRF wrapper.
--
-- If both live in one undifferentiated table, Stage 4 has no way to tell which
-- rows to migrate and which are supposed to stay custodied — and it would find
-- out by breaking the ones it moved. Hence a column now, before there is any
-- data to backfill.
-- ---------------------------------------------------------------------------

-- A third axis, and deliberately not folded into the two that exist.
--
--   `status` — may this identity act at all
--   `role`   — what may it do while active (admin / member)
--   `kind`   — what sort of principal it is
--
-- Conflating `kind` with `role` would make "an admin bot" unrepresentable, and
-- conflating it with `status` would make a disabled bot indistinguishable from
-- a disabled person. They answer different questions.
alter table users
  add column kind text not null default 'human'
  check (kind in ('human', 'role'));

-- ---------------------------------------------------------------------------
-- Service credentials
--
-- `/sign` takes a Bearer token whose subject is a pubkey, and every route that
-- issues one needs a human session — a session cookie, or the authorization
-- code flow that ends in one. A role identity has nobody to sign in, so before
-- this it could hold a key and never use it.
--
-- The answer is the client-credentials grant: an app authenticates as itself
-- and receives a token for the role it is registered to act as. That keeps the
-- ten-minute token TTL and introduces no long-lived bearer — the secret is
-- exchanged for a short token, rather than being one.
--
-- **This makes such an app a confidential client**, which browser apps are not
-- and must never be: a secret shipped in a bundle is public. Peek and Ship stay
-- exactly as they are, with a null secret, and the grant refuses them.
-- ---------------------------------------------------------------------------

alter table app_credentials
  -- SHA-256 of the secret, never the secret. Null means a public client, which
  -- is what every browser app is and stays.
  add column client_secret_hash bytea,

  -- The role identity this credential signs as. `restrict` rather than
  -- `cascade`: deleting an identity out from under a live credential would
  -- leave an app authenticating successfully and signing as nobody, so the
  -- credential has to be dealt with first.
  add column acts_as_user_id uuid references users(id) on delete restrict;

-- Acting as a role requires authenticating as something. A credential with an
-- `acts_as` and no secret would be an app that anybody could impersonate to
-- sign as the role, which is the whole risk this table exists to bound.
alter table app_credentials
  add constraint app_credentials_acts_as_needs_secret
  check (acts_as_user_id is null or client_secret_hash is not null);

-- One credential per role. Two credentials signing as the same identity is not
-- obviously wrong, but nothing needs it yet and the audit trail is clearer when
-- "which credential signed this" has one answer.
create unique index app_credentials_acts_as_idx
  on app_credentials (acts_as_user_id)
  where acts_as_user_id is not null;
