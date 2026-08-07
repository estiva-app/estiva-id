#!/usr/bin/env bash
#
# Whole-box backup. Lives at /opt/backup/backup.sh, run nightly by a systemd
# timer. Covers Estiva ID *and* the relay — it is one machine, and a restore
# that recovers only half of it is not a restore.
#
# ## What makes this safe to store anywhere
#
# Everything is encrypted to an **age public key**. The private half is not on
# this machine — it lives in a password manager. So the server can write
# backups it cannot itself read, and a stolen backup (or a compromised backup
# host) yields ciphertext rather than every identity in the system.
#
# That is a stronger property than keeping dumps and secrets in separate
# locations, which was the original plan: separation protects you only until
# someone reaches both places, whereas this protects the archive itself.
#
# ## What is inside, and why the secrets are in there too
#
#   * `estiva-id.sql`  — users, passkeys, **encrypted Nostr keys**, audit log
#   * `buzz.sql`       — events, channels, memberships
#   * `estiva-id.env`  — includes KEY_ENCRYPTION_KEK, which is what makes
#                        `user_keys.envelope` decryptable. The database without
#                        it is unrecoverable ciphertext.
#   * `buzz.env`       — includes BUZZ_RELAY_PRIVATE_KEY, the relay's identity
#   * `minio.tar`      — Blossom blobs (avatars and uploads)
#
# Including the `.env` files makes a restore self-contained: one archive plus
# one age key rebuilds the box. The alternative — keeping them out — means a
# restore needs the archive *and* several password-manager entries, and the
# entry everyone forgets is the one that makes the rest worthless.
#
# The KEK is *also* held separately in a password manager. That redundancy is
# deliberate: it is the one value whose loss cannot be recovered from anything.
set -euo pipefail

DEST="${DEST:-/var/backups/estiva}"
RECIPIENT_FILE="${RECIPIENT_FILE:-/opt/backup/recipient.pub}"
KEEP="${KEEP:-14}"

log() { echo "[$(date -Is)] $*"; }
fail() { log "FAILED: $*"; exit 1; }

[[ -r "$RECIPIENT_FILE" ]] || fail "no recipient key at $RECIPIENT_FILE"
RECIPIENT="$(tr -d '[:space:]' < "$RECIPIENT_FILE")"
[[ -n "$RECIPIENT" ]] || fail "recipient key is empty"

mkdir -p "$DEST"
chmod 700 "$DEST"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
chmod 700 "$WORK"

STAMP="$(date -u +%Y%m%d-%H%M%S)"
OUT="$DEST/estiva-$STAMP.tar.gz.age"

# --- databases -------------------------------------------------------------
# No -t: a TTY would corrupt the dump with carriage returns.
log 'dumping estiva-id'
docker exec estiva-id-postgres-1 pg_dump -U estiva_id -d estiva_id > "$WORK/estiva-id.sql" \
  || fail 'estiva-id pg_dump'
[[ -s "$WORK/estiva-id.sql" ]] || fail 'estiva-id dump is empty'

log 'dumping buzz'
docker exec buzz-prod-postgres-1 pg_dump -U buzz -d buzz > "$WORK/buzz.sql" \
  || fail 'buzz pg_dump'
[[ -s "$WORK/buzz.sql" ]] || fail 'buzz dump is empty'

# --- config, including the keys the dumps are useless without --------------
cp /opt/estiva-id/.env "$WORK/estiva-id.env" || fail 'estiva-id .env'
cp /opt/buzz/.env "$WORK/buzz.env" || fail 'buzz .env'

# --- object storage --------------------------------------------------------
log 'archiving minio'
docker run --rm -v buzz-prod_buzz-minio-data:/data:ro -v "$WORK":/out alpine \
  tar -C /data -cf /out/minio.tar . || fail 'minio archive'

# --- seal ------------------------------------------------------------------
# Written to a temp name and moved into place only on success, so a crash
# mid-write never leaves a truncated archive looking like a good backup.
log 'encrypting'
tar -C "$WORK" -czf - . | age -r "$RECIPIENT" > "$OUT.partial" || fail 'encrypt'
mv "$OUT.partial" "$OUT"
chmod 600 "$OUT"

# age files start with "age-encryption.org/v1" — cheap proof we wrote a real
# archive rather than an empty file or a shell error.
head -c 21 "$OUT" | grep -q 'age-encryption.org' || fail 'output is not an age file'

log "wrote $OUT ($(du -h "$OUT" | cut -f1))"

# --- retention -------------------------------------------------------------
mapfile -t OLD < <(ls -1t "$DEST"/estiva-*.tar.gz.age 2>/dev/null | tail -n +$((KEEP + 1)))
for f in "${OLD[@]:-}"; do
  [[ -n "$f" ]] && rm -f "$f" && log "pruned $(basename "$f")"
done

log "done — $(ls -1 "$DEST"/estiva-*.tar.gz.age 2>/dev/null | wc -l) archive(s) retained"
