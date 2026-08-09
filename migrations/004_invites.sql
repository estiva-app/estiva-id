-- ---------------------------------------------------------------------------
-- Invites, and the first notion of an admin (PEEK-65)
--
-- Registration has been open since the service was built: anyone who could
-- reach the origin could mint an identity, and each one mints a custodied Nostr
-- keypair. That was tolerable only because you had to know the API — and the
-- registration screen (PEEK-68) removes exactly that barrier, which is why the
-- gate lands with the screens rather than after them.
-- ---------------------------------------------------------------------------

-- Who may invite. Two values, because that is what is actually needed today.
--
-- Not the same axis as `status`: status says whether a person may act at all,
-- role says what they may do while active. Conflating them would make
-- "suspended admin" unrepresentable.
--
-- Deliberately minimal. Role and service identities are PEEK-34, and this is a
-- boolean wearing a text column so that ticket can extend it rather than
-- migrate away from a `bool is_admin`.
alter table users
  add column role text not null default 'member'
  check (role in ('admin', 'member'));

-- ---------------------------------------------------------------------------
-- Invites
--
-- A time-boxed, single-use link. No password is created or sent, because there
-- is no password in this design — the link's only job is to authorise one
-- passkey enrolment.
--
-- Stage 1 has no mailer on purpose: the admin creates the person and copies the
-- link into a DM. Same flow, no provider dependency, and the mailer arrives
-- when handing links over by hand gets annoying.
-- ---------------------------------------------------------------------------

create table invites (
  id              uuid primary key default gen_random_uuid(),

  -- SHA-256 of the token, never the token. The link is a bearer credential
  -- that will sit in someone's chat history; a database dump must not yield
  -- working invites.
  token_hash      bytea not null unique,

  -- What the admin filled in, so the person enrolling does not retype it and
  -- cannot quietly change it. The email is the identity's, and letting the
  -- invitee edit it would make an invite transferable to anyone.
  email           text not null,
  display_name    text,
  -- Optional: the handle to claim on enrolment. Nothing enforces uniqueness
  -- here — `user_handles` does that at the moment of the claim, because two
  -- invites naming the same handle is a conflict only if both are redeemed.
  handle          text,
  role            text not null default 'member' check (role in ('admin', 'member')),

  -- Null for the bootstrap invite, which is minted by a script on the box
  -- because there is no admin yet to attribute it to. That is also the only
  -- way in on a fresh deployment, and it deliberately requires shell access.
  created_by      uuid references users(id) on delete set null,

  expires_at      timestamptz not null,

  -- The user row created when the invite was opened. Set at
  -- `/auth/register/options`, before enrolment can succeed, so a person who
  -- abandons the passkey prompt can come back to the same link and the same
  -- account rather than stranding both.
  claimed_user_id uuid references users(id) on delete cascade,

  -- Single use, and set only once a passkey is actually enrolled. Consuming at
  -- `/options` instead would burn the invite on a cancelled browser prompt,
  -- which is the most common way enrolment fails.
  consumed_at     timestamptz,

  created_at      timestamptz not null default now()
);

create index invites_email_idx on invites (lower(email));
create index invites_expiry_idx on invites (expires_at) where consumed_at is null;
