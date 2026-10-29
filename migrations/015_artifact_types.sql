-- ---------------------------------------------------------------------------
-- Which file types an app may save (dce43a38)
--
-- A file is now an upstream Buzz artifact, `kind:45010`, and every app saves
-- the same kind: what tells a project from a Leaf document is its `type` tag.
-- So `allowed_kinds` alone would let any credential holding 45010 save every
-- type there is. This list narrows 45010 to the types an app is listed for,
-- checked beside the kind in `domain/policy.ts`.
--
-- Empty refuses every type, so granting 45010 without a list signs nothing.
-- It limits what Estiva's apps sign through `/sign`, not what the relay accepts.
--
-- why: https://github.com/estiva-app/estiva-docs/blob/main/decisions/every-file-is-an-artifact-the-relay-keeps-in-order.md
-- ---------------------------------------------------------------------------

alter table app_credentials
  add column allowed_types text[] not null default '{}';
