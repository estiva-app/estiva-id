-- PEE-4: which relays an app may answer a NIP-42 challenge from.
--
-- A separate column from `nip98_url_prefixes`, which holds the same origin
-- today and is the tempting place to put this. They are two capabilities:
-- NIP-98 reaches the relay's HTTP bridge as a client, NIP-42 authenticates the
-- *user* to a relay over a socket. Collapsed into one column, widening an app's
-- bridge access would silently widen what it can authenticate to, and there
-- would be no way to grant one without the other.
--
-- Empty means none, matching `nip98_url_prefixes`. Every existing row therefore
-- gains the column already fail-closed, and kind:22242 stays refused until a row
-- is deliberately given a relay — which is what makes this migration safe to
-- apply before the seed that grants Peek the kind.
alter table app_credentials
  add column relay_auth_urls text[] not null default '{}';

comment on column app_credentials.relay_auth_urls is
  'Relay URLs this app may sign a NIP-42 (kind 22242) challenge response for. Matched exactly after URL normalization, never by prefix. Narrows, and never widens, SIGN_RELAY_AUTH_ALLOWED_URLS.';
