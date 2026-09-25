-- ---------------------------------------------------------------------------
-- Delegated sessions: a person's bot holds a session as them (PER-22)
--
-- Every authenticated check in a browser — a click-through, a console dump of
-- read state — has been a checklist the person runs and pastes back, because
-- the agent has no way to be signed in as them. This is that way, and it is
-- shaped by what makes it safe rather than by what makes it convenient:
--
--   * **The bot asks, the person approves with a passkey.** The device flow
--     (RFC 8628, the `npm login` shape): the bot authenticates with its own
--     client secret, gets a short code, and the person opens a link and
--     approves with a fresh passkey assertion. A session cookie the person
--     already has is not enough — the approval is a ceremony of its own.
--   * **Only the bot's owner may approve.** A bot can only ever become the
--     person who steers it, so a code sent to anybody else is refused and the
--     flow cannot be used to phish a colleague.
--   * **What it yields is a session, marked as delegated.** The consumer is a
--     headless browser driving the real apps, which sign in through
--     `/authorize` like anybody else. Every token minted from that session
--     names the bot (`act`), every event `/sign` signs for it carries a
--     `client` tag naming the bot, and every grant and use is audited.
--   * **It reaches app sign-in only.** A delegated session is refused by the
--     account and admin surfaces — no passkeys, invites, offboarding or bot
--     secrets — so a leaked cookie is a day of the person's apps, not an
--     administrator.
--   * **Revoking it stops the next request.** `/sign` and `/nip44` re-check the
--     session on every call for a delegated token, rather than trusting the
--     token's own expiry.
-- ---------------------------------------------------------------------------

-- The bot a session belongs to, when it is not the person's own.
--
-- `client_id` of the bot's service credential rather than the bot's user id:
-- it is what the device grant authenticated, what `act.sub` names in every
-- token, and what the audit trail already calls `actor_client_id`.
--
-- `restrict`, like `acts_as_user_id`: a live delegation whose credential row
-- vanished would be a session nobody could attribute.
alter table sessions
  add column delegate_client_id text references app_credentials(client_id) on delete restrict,

  -- The `client` tag `/sign` adds to every event signed through this session,
  -- composed once at approval so the tag and the audit row agree.
  add column delegate_tag text;

alter table sessions
  add constraint sessions_delegate_has_tag
  check ((delegate_client_id is null) = (delegate_tag is null));

create index sessions_delegate_idx on sessions (user_id)
  where delegate_client_id is not null and revoked_at is null;

-- A ceremony of its own, for the same reason `recovery` has one: an approval
-- assertion must not be redeemable as a sign-in, and a sign-in assertion must
-- not approve anything.
alter table webauthn_challenges
  drop constraint webauthn_challenges_ceremony_check;

alter table webauthn_challenges
  add constraint webauthn_challenges_ceremony_check
  check (ceremony in ('registration', 'authentication', 'recovery', 'delegation'));

-- ---------------------------------------------------------------------------
-- Pending requests
--
-- `device_code` is the bot's polling credential and is stored hashed, like
-- every other bearer secret here. `user_code` is what the person types or
-- follows a link to: short, human, and useless without both a passkey and
-- being the bot's owner, so it is stored as-is to be looked up.
-- ---------------------------------------------------------------------------

create table device_authorizations (
  id               uuid primary key default gen_random_uuid(),
  device_code_hash bytea not null unique,
  user_code        text not null unique,

  -- Who asked. The bot's credential, and through it the bot and its owner.
  client_id        text not null references app_credentials(client_id) on delete cascade,

  -- A free-text hint from the requester ("WSL on miky-desktop"), shown on the
  -- approval screen so a person can tell two requests apart. Never trusted.
  label            text,

  status           text not null default 'pending'
                   check (status in ('pending', 'approved', 'denied', 'redeemed')),

  -- The challenge the approval assertion must sign, bound to this request so an
  -- assertion over one request cannot approve another.
  approval_challenge text,

  approved_by_user_id uuid references users(id) on delete cascade,
  approved_credential_id uuid references webauthn_credentials(id) on delete set null,
  approved_at      timestamptz,

  -- Set when the bot collects the session, which is also when the request dies.
  session_id       uuid references sessions(id) on delete set null,

  created_at       timestamptz not null default now(),
  expires_at       timestamptz not null,
  last_polled_at   timestamptz,

  constraint device_authorizations_approval_is_whole
    check ((status in ('approved', 'redeemed')) = (approved_by_user_id is not null))
);

create index device_authorizations_expiry_idx on device_authorizations (expires_at);
