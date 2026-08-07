-- ---------------------------------------------------------------------------
-- The public profile (PEEK-31)
--
-- Estiva ID becomes the *sole* publisher of kind:0. Until now two apps
-- published profiles — Peek's `convex/nostr/publish.ts` and Ship's
-- `src/store.ts` — which is why one human could render as two different people.
-- One writer is the structural fix; these columns are what it writes from.
--
-- `users.email` stays private and deliberately has no counterpart here: the
-- split between a private directory attribute and a published profile is the
-- point of having both.
-- ---------------------------------------------------------------------------

-- Avatar URL as published in kind:0.
--
-- Peek publishes a Convex storage URL today, which ties an ecosystem-wide
-- avatar to one deployment's lifetime. The destination is a content-addressed
-- Blossom blob on the relay (PEEK-42); this column holds whichever URL is
-- current and does not care which of the two it is.
alter table users add column picture text;

-- ---------------------------------------------------------------------------
-- nip05 handles
--
-- **Keyed by (person, community host), never by person alone.** A handle's
-- domain must equal the community host exactly — Buzz's `canonicalize_nip05()`
-- requires it and `extract_domain()` does not strip subdomains — so the same
-- pubkey is `jan@estiva.estiva.app` in one workspace and `jan@chat.acme.com`
-- in another. A single `nip05_handle` column on `users` is the shape that has
-- to be undone later (OPEN-SEAMS.md), so it is not built.
--
-- The host is the natural key and needs no `workspaces` table to exist yet.
-- When PEEK-83 splits workspaces out, this gains a foreign key; it does not
-- need a data migration, because the host is already the thing that identifies
-- a workspace to a relay.
-- ---------------------------------------------------------------------------

create table user_handles (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references users(id) on delete cascade,

  -- The community host this handle is valid at, exactly as the relay resolves
  -- it from the Host header. Lowercase; no scheme, no port, no trailing dot.
  community_host text not null,

  -- The local part only — `jan`, not `jan@estiva.estiva.app`. Storing the
  -- domain twice is how the two drift apart. NIP-05 restricts the local part
  -- to a-z0-9-_. and the relay resolves `?name=` case-insensitively, so it is
  -- stored lowercase and compared as stored.
  handle         text not null
                 check (handle ~ '^[a-z0-9\-_.]+$'),

  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now(),

  -- One handle per person per workspace: the profile has a single `nip05`
  -- field, so a second row for the same host would make "which one gets
  -- published" a coin toss.
  unique (user_id, community_host),

  -- And a handle means one person within a workspace. Without this, two people
  -- can publish the same `nip05` and the relay's last writer silently wins the
  -- name — a namespace collision that looks like an impersonation.
  unique (community_host, handle)
);

create index user_handles_host_idx on user_handles (community_host);
