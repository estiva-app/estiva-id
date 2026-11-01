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
-- With the type list gone, a 45010 grant would sign every type, so the kind
-- leaves every credential too, not only the seeded ones: a role or
-- self-service credential holding it signed nothing under 015 and must not
-- sign more now.
--
-- why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/a-file-is-its-fields-each-kept-in-order-by-the-relay.md
-- ---------------------------------------------------------------------------

update app_credentials
  set allowed_kinds = array_remove(allowed_kinds, 45010), updated_at = now()
  where 45010 = any(allowed_kinds);

alter table app_credentials
  drop column allowed_types;
