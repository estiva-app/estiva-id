#!/usr/bin/env bash
#
# Pull encrypted backups from the server to this machine.
#
# Runs on the laptop, not the box. A stopgap until backups go somewhere that
# does not depend on anyone remembering: it only protects you as often as you
# run it, so run it before anything risky and after anything important.
#
# What lands here is ciphertext. The age key that opens it is in a password
# manager and deliberately not on this machine either, so a stolen laptop gets
# an unreadable pile of 40 KB files.
set -euo pipefail

HOST="${HOST:-root@167.233.252.136}"
REMOTE="${REMOTE:-/var/backups/estiva}"
DEST="${DEST:-$HOME/estiva-backups}"

mkdir -p "$DEST"
chmod 700 "$DEST"

# The key usually lives in a keychain-managed agent rather than being loaded by
# default, so a bare ssh here fails with "Permission denied (publickey)".
if [[ -z "${SSH_AUTH_SOCK:-}" && -r "$HOME/.keychain/$(hostname)-sh" ]]; then
  # shellcheck source=/dev/null
  . "$HOME/.keychain/$(hostname)-sh"
fi

echo "pulling from $HOST:$REMOTE"

if command -v rsync >/dev/null 2>&1; then
  rsync -a --ignore-existing --info=stats2 \
    "$HOST:$REMOTE/estiva-*.tar.gz.age" "$DEST/"
else
  scp -q "$HOST:$REMOTE/estiva-*.tar.gz.age" "$DEST/"
fi

chmod 600 "$DEST"/estiva-*.tar.gz.age 2>/dev/null || true

# Check what arrived is actually an age archive rather than an error page, a
# truncated transfer, or an empty file. A backup nobody validated is a rumour.
bad=0
for f in "$DEST"/estiva-*.tar.gz.age; do
  [[ -e "$f" ]] || continue
  if ! head -c 21 "$f" | grep -q 'age-encryption.org'; then
    echo "  CORRUPT: $(basename "$f")"
    bad=$((bad + 1))
  fi
done

count=$(ls -1 "$DEST"/estiva-*.tar.gz.age 2>/dev/null | wc -l)
newest=$(ls -1t "$DEST"/estiva-*.tar.gz.age 2>/dev/null | head -1)

echo "held locally: $count archive(s) in $DEST"
[[ -n "$newest" ]] && echo "newest:       $(basename "$newest")"
if (( bad > 0 )); then
  echo "$bad archive(s) failed the format check — do not trust them"
  exit 1
fi
