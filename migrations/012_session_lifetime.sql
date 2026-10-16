-- ---------------------------------------------------------------------------
-- A sign-in lasts while it is used: 7 days unused, 14 days at most
--
-- Until now a session ended 12 hours after the passkey tap, however much it was
-- used, so every working day began with a tap. It now ends at the earlier of
-- two moments (Miky, 2026-10-16):
--
--   * `expires_at`, 14 days after the tap, which never moves; and
--   * `idle_expires_at`, 7 days after the last use, which every renewal and
--     every visit to this origin moves forward.
--
-- `authenticated_at` is when the passkey (or a test account's secret) was last
-- presented for this session. The 14 days count from it, and the re-check
-- before passkey changes reads it.
--
-- Delegated sessions keep their fixed 24 hours: `idle_expires_at` stays null
-- for them, and null means "no idle end". Rows from before this migration get
-- null too, and end on their own 12 hours.
-- ---------------------------------------------------------------------------

alter table sessions
  add column authenticated_at timestamptz,
  add column idle_expires_at  timestamptz;

update sessions set authenticated_at = created_at;

alter table sessions
  alter column authenticated_at set not null,
  alter column authenticated_at set default now();
