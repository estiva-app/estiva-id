# Deploying Estiva ID

Target: the Hetzner box (`167.233.252.136`), reached through the `estiva-prod`
Cloudflare Tunnel. Public URL `https://id.estiva.app`.

## How this deploy works, and why

**Nothing connects inward.** The Hetzner firewall allows TCP 22 from one address,
and there are no inbound web ports at all — `cloudflared` dials *out* to
Cloudflare. So CI cannot SSH here, and is not given a key that would let it.

CI's only job is to publish an image. The box decides when to take it:

```
push to main → CI: lint, typecheck, test → build → ghcr.io/estiva-app/estiva-id:main
                                                            ↓
                          systemd timer on the box, every 2 min → update.sh
                                                            ↓
                                    pull → migrate → restart → health check
```

The cost is up to two minutes of deploy lag. The gain is no standing credential
for an access path that is deliberately closed.

**TLS is Cloudflare's job.** No Caddy, no Let's Encrypt, no certificates on the
box. The service speaks plain HTTP on `127.0.0.1:8787`.

---

## First deploy, by hand

### 1. Register the hostname on the tunnel

**The `estiva-prod` tunnel is dashboard-managed**, confirmed by its service unit:

```
ExecStart=/usr/bin/cloudflared --no-autoupdate tunnel run --token-file /etc/cloudflared/token
```

`--token-file` means routing lives in Cloudflare's dashboard, not on the server.
**Editing `/etc/cloudflared/config.yml` does nothing** for this tunnel, and
`cloudflared tunnel route dns` is unnecessary — the dashboard creates the DNS
record when the hostname is added.

So, in https://one.dash.cloudflare.com → **Networks** → **Tunnels** →
**estiva-prod** → **Public Hostname** → **Add a public hostname**:

| Field | Value |
| -- | -- |
| Subdomain | `id` |
| Domain | `estiva.app` |
| Path | *(empty)* |
| Type | `HTTP` |
| URL | `localhost:8787` |

`HTTP`, not `HTTPS`: that is the hop from `cloudflared` to the local container,
which has no certificate. The public side is HTTPS regardless — Cloudflare
terminates it at the edge.

Repeat for each service later: `estiva.estiva.app` → the relay's port,
`peek.estiva.app` → Peek's. See
[`cloudflared-ingress.example.yml`](cloudflared-ingress.example.yml) only if the
tunnel is ever converted to file-managed.

### 2. Make the image pullable from the box

**A new GHCR package is private by default**, even when its repository is public,
so the box cannot pull it yet. Anonymous `docker pull ghcr.io/estiva-app/estiva-id:main`
fails with `unauthorized` until this is fixed.

Preferred, since the repo is public anyway:

> GitHub → the `estiva-app` org → **Packages** → `estiva-id` → **Package settings**
> → **Change visibility** → Public.

The box then needs no registry credentials at all, which keeps the "no standing
secrets on the server" posture.

If the image must stay private, create a read-only PAT with `read:packages` and
`docker login ghcr.io` **on the server** — never in GitHub Actions secrets, which
have no use for it.

### 3. Lay out the deploy directory

From a machine that has this repo checked out (SSH is restricted to the home IP,
so it has to be that one):

```bash
ssh root@167.233.252.136 'mkdir -p /opt/estiva-id'
scp deploy/docker-compose.yml deploy/update.sh deploy/estiva-id-update.service deploy/estiva-id-update.timer root@167.233.252.136:/opt/estiva-id/
```

Fetching these from GitHub on the server does not work while the repository is
private — only the *package* is public, which is all the deploy needs.

Then on the server:

```bash
chmod +x /opt/estiva-id/update.sh
```

### 4. Fill in `.env` — and back up the KEK immediately

```bash
openssl rand -hex 24   # POSTGRES_PASSWORD
openssl rand -hex 32   # KEY_ENCRYPTION_KEK
```

> **Record `KEY_ENCRYPTION_KEK` somewhere separate from the database backups,
> now — before the first user registers.**
>
> It decrypts every user's custodied Nostr key. Lose it and every identity in
> the database is unrecoverable ciphertext: there is no recovery path, and
> everyone's relay history stays signed by keys nobody can ever use again. Leak
> it *alongside* a database dump and the holder can sign as anyone.
>
> Those two failure modes are why the KEK and the dumps must never share a
> location. See PEEK-63.

`.env` should be `chmod 600` and owned by root.

### 5. Start it

```bash
cd /opt/estiva-id
docker compose pull
docker compose up -d postgres
docker compose run --rm -T estiva-id node dist/db/migrate.js
docker compose up -d estiva-id
```

Seed the app credentials — this is what `/sign` reads its per-app policy from,
and without it every signing request is refused as an unknown app:

```bash
docker compose run --rm -T estiva-id node dist/db/seed.js
```

### 6. Verify through the tunnel

```bash
curl https://id.estiva.app/healthz
curl https://id.estiva.app/readyz
curl https://id.estiva.app/.well-known/openid-configuration
curl https://id.estiva.app/.well-known/jwks.json
```

`readyz` must report `"database":"ok"` and JWKS must return one key. That closes
PEEK-85 and the last outstanding criterion on PEEK-25.

### 7. Turn on automatic deploys

```bash
cp estiva-id-update.service estiva-id-update.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now estiva-id-update.timer
```

Check it:

```bash
systemctl list-timers estiva-id-update
journalctl -u estiva-id-update -f
```

### 8. Remove the validation container

```bash
docker rm -f estiva-test
```

---

## Operating it

**Watch a deploy:** `journalctl -u estiva-id-update -f`

**Deploy now, without waiting:** `systemctl start estiva-id-update`

**Roll back:** every build is also tagged with its commit sha.

```bash
cd /opt/estiva-id
docker compose stop estiva-id
docker run ... ghcr.io/estiva-app/estiva-id:<sha>
```

Pin the sha in `docker-compose.yml` and **stop the timer first**, or it will pull
`main` over your rollback within two minutes:

```bash
systemctl stop estiva-id-update.timer
```

**A migration that fails** aborts the deploy and leaves the previous container
running against the schema it was built for. That is deliberate: a stale service
is recoverable, a new binary on an unmigrated database is not. Fix forward with a
new migration — the runner refuses to re-run an applied file whose contents have
changed, so editing one is not an option.

## Testing this stack on a dev machine

The compose project here is named `estiva-id`; the repo's development stack is
`estiva-id-dev`, so the two can run side by side without one recreating the
other's containers.

Point it at a locally built image rather than GHCR:

```bash
docker build -t estiva-id:local . && ESTIVA_ID_IMAGE=estiva-id:local docker compose up -d
```

On Docker Desktop under WSL, ports published to `127.0.0.1` are not forwarded
into the WSL loopback, so `curl localhost:8787` fails even though the container
is healthy. Check from inside instead — this is a local quirk and not how the
Linux box behaves:

```bash
docker exec estiva-id-estiva-id-1 node -e "fetch('http://127.0.0.1:8787/readyz').then(r=>r.text()).then(console.log)"
```

## What is not automated

- **Backups** (PEEK-63) — the KEK and both databases. Urgent, and needed before
  the first real registration.
- **Log shipping.** Logs are JSON on stdout, held only by the local journal.
- **Monitoring.** Nothing watches `/readyz`. Worth fixing before Stage 2, when
  an outage here stops publishing across every app.
