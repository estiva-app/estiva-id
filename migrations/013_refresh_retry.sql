-- ---------------------------------------------------------------------------
-- A renewal whose answer was lost can be asked again for 30 seconds
--
-- A refresh token is single-use, and presenting a spent one revokes its whole
-- chain as theft (RFC 9700 §4.14.2). That also signed out an app whose renewal
-- reached this service but whose answer never came back: a laptop going to
-- sleep, a dropped Wi-Fi. It still held only the spent token, and retrying it
-- ended the sign-in (Miky, 2026-10-16: a retry within 30 seconds gets the same
-- new token, and a use after that still ends the chain).
--
-- Answering a retry with the *same* successor needs the successor, and only
-- hashes are stored. So the spent row keeps it, sealed:
--
--   * `successor_id` is the row that replaced this one, so a retry can check
--     the successor is still unused;
--   * `successor_sealed` is the successor token, AES-256-GCM under a key
--     derived from the spent token itself (`domain/refresh.ts`). Only someone
--     presenting the spent token can open it, and the database alone, which
--     holds nothing but the spent token's SHA-256, cannot. It is cleared when
--     the chain is revoked, and every renewal clears the ones past their 30
--     seconds, so it outlives its use only until the next renewal anyone makes.
-- ---------------------------------------------------------------------------

alter table refresh_tokens
  add column successor_id     uuid references refresh_tokens(id) on delete set null,
  add column successor_sealed bytea;

create index refresh_tokens_sealed_idx on refresh_tokens (used_at)
  where successor_sealed is not null;
