-- ---------------------------------------------------------------------------
-- Who a bot belongs to (PEEK-164)
--
-- A role identity has no owner today, and that was correct while every one of
-- them was the workspace's: `Relay Operator` must outlive whoever set it up,
-- and `roles.ts` argues the point directly — "for a role there is no human to
-- hold a key, so the org genuinely is the principal and custody is correct
-- forever."
--
-- It stopped being the whole picture the moment bots became personal.
-- `docs/claude-desktop-setup.md` instructs an admin to create **one identity
-- per person**, named for them, and production now holds one called
-- "Claude (steered by Miky)". That name asserts an ownership the schema cannot
-- express, and nothing enforces.
--
-- ## The hole this closes
--
-- `offboardPerson` revokes passkeys, sessions, the handle and relay admission.
-- It has never touched `app_credentials`, and under org custody that was right
-- — the bot was never theirs. With a personal bot it means **offboarding
-- somebody leaves their agent reading and writing the workspace with a
-- credential nobody revoked**, which is worse than not having offboarded them:
-- the person is gone, so nobody is watching what their bot does.
--
-- ## Why a column and not a third `kind`
--
-- A personal bot *is* a role identity. Everything that already refuses a role
-- the human paths — recovery above all, which would mint a passkey that signs
-- as the bot forever — must keep refusing it, and a new `kind` value would make
-- every one of those checks silently stop applying to bots.
--
-- So ownership is an attribute of a role, not a different species:
--
--   owner_user_id IS NULL      → the workspace's. Outlives everyone.
--   owner_user_id IS NOT NULL  → that person's. Dies with their access.
--
-- `on delete restrict` deliberately: a person with a live bot cannot be deleted
-- out from under it, because that would leave a credential whose owner cannot
-- be found. Offboarding is the supported exit and it cascades.
-- ---------------------------------------------------------------------------

alter table users
  add column owner_user_id uuid references users(id) on delete restrict;

-- Only a role can be owned. A human with an owner would be a person somebody
-- else can revoke, which is not a thing this service should be able to express.
alter table users
  add constraint users_owner_only_for_roles
  check (owner_user_id is null or kind = 'role');

-- An owner must be a human, because the mechanism is offboarding and only a
-- human gets offboarded. That is **not** expressible as a CHECK — it is a
-- statement about another row — so `createRoleIdentity` enforces it and this
-- comment exists so nobody reads the constraint above as covering it.
create index if not exists users_owner_user_id_idx on users (owner_user_id)
  where owner_user_id is not null;
