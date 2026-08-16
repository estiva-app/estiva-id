-- ---------------------------------------------------------------------------
-- Refresh tokens (PEEK-108)
--
-- Until now an access token dying was the end of the session as far as a
-- browser app was concerned: there was no refresh grant, and the only recovery
-- was a top-level redirect through `/authorize`, which costs the page and
-- everything on it. The mitigation was raising `JWT_TTL_SECONDS` to an hour,
-- which bought comfort by widening the window a leaked token stays useful.
--
-- A refresh grant is what lets the access token be short *again* and the
-- session stay long, which is the whole point of having one.
--
-- ## Why this is riskier than an authorization code, and what answers it
--
-- A code lives 60 seconds and is used once, in a redirect the person is
-- watching. A refresh token lives as long as the session and sits in a public
-- client's storage, where nothing can keep a secret. Three properties carry it:
--
--   1. **Rotation.** Every redemption issues a new token and consumes the old
--      one. A token is a single-use credential exactly like a code.
--   2. **Reuse detection.** Presenting an already-consumed token is not a
--      retry, it is evidence that two parties hold the same credential — so it
--      revokes the entire chain rather than just refusing. The legitimate app
--      is signed out too, which is the correct outcome: somebody has a copy.
--   3. **Session binding.** A refresh token is only as alive as the session
--      that justified it. Redemption re-checks it, so `/logout` and offboarding
--      end refresh without needing to hunt down rows.
-- ---------------------------------------------------------------------------

create table refresh_tokens (
  id           uuid primary key default gen_random_uuid(),

  -- SHA-256 of the token, never the token — same posture as `sessions` and
  -- `authorization_codes`. A dump must not yield a live credential.
  token_hash   bytea not null unique,

  client_id    text not null references app_credentials(client_id) on delete cascade,
  user_id      uuid not null references users(id) on delete cascade,

  -- The session that justified this token. Redemption joins here and requires
  -- it to still be live, which is what makes signing out actually end refresh
  -- rather than merely stop new sign-ins (PEEK-122).
  session_id   uuid not null references sessions(id) on delete cascade,

  -- The rotation chain. Every token minted from a redemption inherits the
  -- family of the one it replaced, so reuse detection can revoke the lineage
  -- rather than the single row that was replayed — the replayed row is already
  -- spent and revoking it alone would achieve nothing.
  family_id    uuid not null,

  -- Never later than the session's own expiry. A refresh token that outlived
  -- the session that justified it would be a way around session lifetime.
  expires_at   timestamptz not null,

  -- Set when rotated. Kept rather than deleted so a replay is *detectable*
  -- rather than merely unsuccessful, exactly as `authorization_codes` does.
  used_at      timestamptz,
  revoked_at   timestamptz,

  created_at   timestamptz not null default now()
);

-- Redemption looks up by hash; everything else is bookkeeping.
create index refresh_tokens_family_idx on refresh_tokens (family_id);
create index refresh_tokens_session_idx on refresh_tokens (session_id);
create index refresh_tokens_expiry_idx on refresh_tokens (expires_at);

-- ---------------------------------------------------------------------------
-- Which session approved a code
--
-- A refresh token is bound to the session that justified it, and the only
-- moment that session is known is `/authorize`. The code carries it across the
-- redirect so the token minted at redemption can inherit the binding.
--
-- Nullable because codes written before this column existed have no session to
-- name — they expire in 60 seconds, so the gap closes itself. A code redeemed
-- without one yields an access token and no refresh token, which is the old
-- behaviour rather than a failure.
-- ---------------------------------------------------------------------------
alter table authorization_codes
  add column session_id uuid references sessions(id) on delete cascade;
