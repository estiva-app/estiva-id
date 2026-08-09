-- ---------------------------------------------------------------------------
-- Handing tokens to browser apps (PEEK-90)
--
-- `POST /token` authenticates with the session cookie, which is `SameSite=Lax`
-- and served without CORS. Both are right for the origin holding every
-- custodied signing key, and together they mean **no app on another origin can
-- obtain a token**. The answer is the redirect flow rather than loosening
-- either: authorization code with PKCE.
-- ---------------------------------------------------------------------------

-- Where an app may be sent back to, matched exactly.
--
-- Exact match, not prefix. A prefix allowlist on an identity provider is an
-- open redirector wearing a disguise: `https://app.test/cb` as a prefix also
-- permits `https://app.test/cb.attacker.example`, and the thing being
-- redirected is an authorization code.
--
-- Empty means this app cannot use the redirect flow at all, which is the
-- correct default — the same fail-closed posture as `nip98_url_prefixes`.
alter table app_credentials add column redirect_uris text[] not null default '{}';

-- ---------------------------------------------------------------------------
-- Authorization codes
--
-- Short-lived, single-use, and bound to four things at once: the app that asked
-- (`client_id`), the person who approved (`user_id`), where the answer may be
-- delivered (`redirect_uri`), and proof that whoever redeems it is whoever
-- started it (`code_challenge`).
--
-- PKCE is what makes this safe for a public client that cannot keep a secret.
-- Without it, anyone who intercepts the code on its way back — a malicious app
-- registered on the same custom scheme, a leaky referrer, browser history —
-- can exchange it. With it, the code is useless without the verifier that never
-- left the app that generated it.
-- ---------------------------------------------------------------------------

create table authorization_codes (
  id             uuid primary key default gen_random_uuid(),

  -- The SHA-256 of the code, never the code. A database dump must not yield
  -- redeemable codes, for the same reason `sessions` stores a hash.
  code_hash      bytea not null unique,

  client_id      text not null references app_credentials(client_id) on delete cascade,
  user_id        uuid not null references users(id) on delete cascade,

  -- Echoed back at redemption and compared. RFC 7636 requires the redirect_uri
  -- to match the one the code was issued for; without it a code issued for one
  -- registered URI could be redeemed as though it came back to another.
  redirect_uri   text not null,

  -- base64url(sha256(code_verifier)). `plain` is not accepted — see the route.
  code_challenge text not null,

  expires_at     timestamptz not null,

  -- Single use. Set on redemption rather than deleting the row, so a replay is
  -- *detectable* rather than merely unsuccessful: a second attempt finds a
  -- consumed code and can be audited as an attack rather than a 404.
  consumed_at    timestamptz,

  created_at     timestamptz not null default now()
);

create index authorization_codes_expiry_idx on authorization_codes (expires_at);
create index authorization_codes_user_idx on authorization_codes (user_id, created_at desc);
