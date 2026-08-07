#!/usr/bin/env bash
# Restore rehearsal: decrypt the newest archive into a scratch stack and prove
# a user whose key was custodied before the backup can still be signed for
# after it. That is the only claim worth making about a backup.
set -euo pipefail
USER_ID="${1:?usage: restore-test.sh <user-id> <expected-pubkey>}"
EXPECT_PUB="${2:?expected pubkey}"

ARCHIVE=$(ls -1t /var/backups/estiva/estiva-*.tar.gz.age | head -1)
WORK=$(mktemp -d); chmod 700 "$WORK"
NET=restore-test-net
cleanup() {
  docker rm -f restore-test-pg >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "archive: $(basename "$ARCHIVE")"
age -d -i /root/estiva-backup-key.txt "$ARCHIVE" | tar -C "$WORK" -xzf -
echo "contents:"; ls -1 "$WORK" | sed 's/^/  /'

KEK=$(grep '^KEY_ENCRYPTION_KEK=' "$WORK/estiva-id.env" | cut -d= -f2)
KID=$(grep '^KEY_ENCRYPTION_KID=' "$WORK/estiva-id.env" | cut -d= -f2)
echo "recovered KEK: ${#KEK} chars, kid=$KID"

docker network create "$NET" >/dev/null
docker run -d --name restore-test-pg --network "$NET" \
  -e POSTGRES_USER=estiva_id -e POSTGRES_PASSWORD=scratch -e POSTGRES_DB=estiva_id \
  postgres:16-alpine >/dev/null
for i in $(seq 1 30); do
  docker exec restore-test-pg pg_isready -U estiva_id -d estiva_id >/dev/null 2>&1 && break
  sleep 2
done

echo "restoring estiva-id.sql into scratch postgres"
docker exec -i restore-test-pg psql -q -U estiva_id -d estiva_id < "$WORK/estiva-id.sql" >/dev/null
echo "users restored: $(docker exec restore-test-pg psql -U estiva_id -d estiva_id -tAc 'select count(*) from users')"
echo "keys restored:  $(docker exec restore-test-pg psql -U estiva_id -d estiva_id -tAc 'select count(*) from user_keys')"

echo "--- signing from restored data, using the KEK out of the backup ---"
docker run --rm --network "$NET" \
  -e DATABASE_URL="postgres://estiva_id:scratch@restore-test-pg:5432/estiva_id" \
  -e ISSUER_URL=https://restore.test -e RP_ID=restore.test -e RP_ORIGINS=https://restore.test \
  -e KEY_ENCRYPTION_KEK="$KEK" -e KEY_ENCRYPTION_KID="$KID" \
  ghcr.io/estiva-app/estiva-id:main node --input-type=module -e "
const { withUserSecretKey } = await import('/app/dist/domain/keys.js');
const { signEvent, verifyEvent } = await import('/app/dist/nostr/keys.js');
const signed = await withUserSecretKey('$USER_ID', (sk, pubkey) =>
  signEvent({ pubkey, created_at: 1785000000, kind: 9, tags: [], content: 'restore rehearsal' }, sk));
const ok = verifyEvent(signed) && signed.pubkey === '$EXPECT_PUB';
console.log(JSON.stringify({ pubkey: signed.pubkey, verified: verifyEvent(signed), matchesOriginal: signed.pubkey === '$EXPECT_PUB' }));
process.exit(ok ? 0 : 1);
" 2>&1 | tail -2
