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
  local id
  id="$(docker image inspect --format '{{.Id}}' "$IMAGE" 2>/dev/null | tail -n1)"
  [[ -n "$id" ]] && echo "$id" || echo 'none'
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

# --force-recreate is load-bearing. Plain `up -d` compares the *service
# definition*, and pulling a new image behind an unchanged `:main` tag does not
# change it — so compose reports "Running", touches nothing, and the deploy
# silently does nothing while reporting success. Observed in production: the
# timer pulled a new image, ran migrations, logged "healthy", and left the old
# container serving for two hours. Worse, the next run saw the image already
# pulled and exited early, so it would never have recovered on its own.
log 'restarting service'
docker compose up -d --force-recreate estiva-id

# Confirm the new container actually serves before calling this a success —
# without it the timer reports success for a container in a crash loop.
#
# Read Docker's own healthcheck rather than curling the published port: it needs
# no tools beyond docker, and it does not care how (or whether) the port is
# published to the host.
container_health() {
  local id
  id="$(docker compose ps -q estiva-id 2>/dev/null || true)"
  [[ -n "$id" ]] || { echo 'missing'; return; }
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$id" 2>/dev/null || echo 'missing'
}

for _ in {1..30}; do
  case "$(container_health)" in
    healthy)
      # Healthy is not the same as updated. Confirm the container is actually
      # running the image we just pulled — the failure this catches reported
      # success while serving stale code, which is the worst kind.
      running="$(docker inspect -f '{{.Image}}' "$(docker compose ps -q estiva-id)" 2>/dev/null || echo unknown)"
      if [[ "$running" != "$after" ]]; then
        log "FAILED: still running ${running:0:19}, expected ${after:0:19}"
        exit 1
      fi
      log "healthy on ${running:0:19}"
      docker image prune -f --filter 'until=168h' >/dev/null 2>&1 || true
      exit 0
      ;;
    unhealthy) break ;;
  esac
  sleep 2
done

log 'FAILED: service did not become healthy after deploy'
docker compose logs --tail 50 estiva-id
exit 1
