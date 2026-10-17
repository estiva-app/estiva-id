-- ---------------------------------------------------------------------------
-- A ceremony for confirming it is still you (AUT-2)
--
-- A sign-in now lasts up to 14 days, so a laptop left signed in is no longer
-- enough to change the account: adding or removing a passkey, signing other
-- devices out, and an admin handing out access or a secret ask for the passkey
-- again once 15 minutes have passed since the last tap (Miky, 2026-10-16).
--
-- Confirming moves the current session's `authenticated_at` and nothing else.
-- It must not open a session, as a sign-in does, and a sign-in challenge must
-- not count as a confirmation, so it is a ceremony of its own — the argument
-- 005 made for `recovery` and 010 for `delegation`.
-- ---------------------------------------------------------------------------

alter table webauthn_challenges
  drop constraint webauthn_challenges_ceremony_check;

alter table webauthn_challenges
  add constraint webauthn_challenges_ceremony_check
  check (ceremony in ('registration', 'authentication', 'recovery', 'delegation', 'reauthentication'));
