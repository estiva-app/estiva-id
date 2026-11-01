-- ---------------------------------------------------------------------------
-- No app saves a file as an artifact any more (fdad50d9)
--
-- 015 narrowed `kind:45010` to the file types an app was listed for, when a
-- project was to be saved as an upstream Buzz artifact. That path is retired:
-- a file is its first record and its fields, each change a `kind:1851` the
-- relay keeps in order, so the kind already says what an app may sign and no
-- seeded app holds 45010. The relay keeps NIP-AR for Buzz's own uses, which
-- never sign through `/sign`.
--
-- why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/a-file-is-its-fields-each-kept-in-order-by-the-relay.md
-- ---------------------------------------------------------------------------

alter table app_credentials
  drop column allowed_types;
