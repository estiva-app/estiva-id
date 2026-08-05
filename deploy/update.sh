#!/usr/bin/env bash
#
# Pull-based deploy. Runs on the box from a systemd timer; nothing connects in.
#
# The Hetzner firewall allows TCP 22 from one address, so CI cannot SSH here and
# should not be given a key that would let it. CI's only job is to publish an
# image; this script decides when to take it.
#
# Ordering is the point: migrations run to completion **before** the new
# container serves traffic. If they fail, the script aborts and the old
# container keeps running against the schema it was built for — a stale service
# is recoverable, a new binary on an unmigrated database is not.

set -euo pipefail

DEPLOY_DIR="${DEPLOY_DIR:-/opt/estiva-id}"
IMAGE="${IMAGE:-ghcr.io/estiva-app/estiva-id:main}"

cd "$DEPLOY_DIR"

log() { echo "[$(date -Is)] $*"; }

current_digest() {
  docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null || echo 'none'
}

before="$(current_digest)"
docker compose pull --quiet estiva-id
after="$(current_digest)"

if [[ "$before" == "$after" ]]; then
  exit 0
fi

log "new image: ${before:0:19} -> ${after:0:19}"

# One-off container on the same compose network and env. Starts Postgres first
# if it is not already up, and is removed whether it succeeds or fails.
log 'running migrations'
docker compose run --rm -T estiva-id node dist/db/migrate.js

log 'restarting service'
docker compose up -d estiva-id

# Confirm the new container actually serves before calling this a success.
# Without this the timer reports success for a container in a crash loop.
for attempt in {1..15}; do
  if curl -fsS --max-time 3 http://127.0.0.1:8787/healthz >/dev/null 2>&1; then
    log 'healthy'
    docker image prune -f --filter 'until=168h' >/dev/null 2>&1 || true
    exit 0
  fi
  sleep 2
done

log 'FAILED: service did not become healthy after deploy'
docker compose logs --tail 50 estiva-id
exit 1
