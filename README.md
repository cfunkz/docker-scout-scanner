# Docker Scout Scanner

A self-hosted vulnerability dashboard for the images on your Docker host. It finds every local image, works out which containers use it, scans it with Trivy and/or Grype, and shows the results on an nginx-served web page over HTTPS. You get a sign-in page, a settings page and an admin panel that only listens on localhost.

It replaces the old `dockerscout_scan.sh` wrapper, which printed `docker scout cves` output for images you picked by hand. Nothing in this version needs a Docker Hub account or a cloud service.

![Overview](docs/screenshots/overview.png)

## What it does that the usual tools don't

Trivy and Grype are great CLIs, but they print a report and stop. Docker Scout's dashboard lives in Docker's cloud. Clair, Harbor and Dependency-Track are built for registries and SBOM programs, and they need Postgres and a lot of setup. This project sits on top of Trivy and Grype and adds the parts you need to *run* vulnerability management on one host:

| | This project | Trivy / Grype CLI | Docker Scout | Clair / Harbor | Dependency-Track |
|---|---|---|---|---|---|
| Self-hosted web UI, no account | ✅ | ❌ | ❌ (cloud dashboard) | ✅ (registry-centric) | ✅ (heavy, Java + DB) |
| Finds local images and running containers on its own | ✅ | ❌ | partly | ❌ | ❌ |
| Re-scan without re-reading the image (SBOM cache) | ✅ | ❌ | ✅ | ✅ | ✅ |
| Two engines merged and cross-checked | ✅ | ❌ | ❌ | ❌ | ❌ |
| Prioritises by EPSS + CISA KEV + "is it running?" | ✅ | Grype: EPSS/KEV columns | partly | ❌ | EPSS |
| Upgrade plan per package, plus a "rebuild the base image" hint | ✅ | ❌ | base image recs | ❌ | ❌ |
| Traces each CVE to the Dockerfile line that added it | ✅ | layer digest only | ✅ | ❌ | ❌ |
| What changed since the last scan / last build of the same tag | ✅ | ❌ | ✅ | ❌ | partly |
| "Where else is CVE-X?" across every image | ✅ | ❌ | ✅ | ❌ | ✅ |
| Accepted risks with expiry, exported as OpenVEX for CI | ✅ | VEX input only | VEX | ❌ | ✅ |
| Alerts to Slack, Discord, ntfy or a webhook on *new* criticals or KEV entries | ✅ | ❌ | paid | ❌ | ✅ |
| Air-gapped / offline mode, no telemetry | ✅ | ✅ | ❌ | ✅ | ✅ |

### Features in detail

- **Automatic inventory.** Listens to Docker events, so new pulls and builds are scanned within seconds, and re-syncs every 2 minutes as a safety net. Each image shows which containers use it and whether they're running.
- **Fast by design.** Each image is read from the daemon **once**, into a CycloneDX SBOM (gzipped on disk). Every later scan, including the automatic re-match after each vulnerability-DB update, runs against that SBOM. In testing, re-scanning 12 images took 1.5 s in total, and a cached re-match of a single image took about 0.15 s. Scans run in parallel (configurable), and an image already in the queue is never queued twice.
- **Risk score (0–100)**, so you don't have to stare at 400 "HIGH"s:
  `severity band × 4 (+ CVSS tiebreak) + √EPSS × 30 + 20 if on the CISA KEV list + 5 if a fix exists + 5 if a container runs the image`. A HIGH that attackers exploit today outranks a CRITICAL that nobody exploits.
- **Fix plan.** Groups fixable findings by package, picks the lowest version that clears all of them, and ranks the upgrades by how much risk each one removes (KEV first). If most findings sit in the base layer, or the base OS is end-of-life, it tells you to rebuild on a newer base instead.
  ![Fix plan](docs/screenshots/fix-plan.png)
- **Layer attribution.** "Introduced by `#3 COPY node_modules /app/node_modules`" versus "`#1 (base) ADD alpine-minirootfs…`" tells you whether to bump the base image or fix your own `RUN` step.
- **End-of-life OS detection.** Flags images whose distribution no longer gets security fixes.
- **Changes tab.** Shows new and resolved findings against the previous scan of the same image, or of the previous build of the same tag, so you can see whether `docker compose pull` actually helped.
- **Fleet view.** One row per CVE across all images, with how many images (and running ones) are affected. Search `CVE-2021-44228` and you get a list of images.
- **Optional secret scanning** for keys and tokens baked into layers. It only re-runs when the image changes.
- **Accepted risks.** Rules match a CVE (or `*`), a package glob and an image glob, need a reason, can expire, and carry an OpenVEX status and justification. They're applied right away, and you can export them as OpenVEX to feed `trivy --vex` or `grype --vex` in CI.
- **Exports:** CSV (with spreadsheet-formula injection neutralised), JSON (with the fix plan), SARIF (for GitHub code scanning), and the CycloneDX SBOM.
- **Notifications** only for *new* findings that match your rules (severity, KEV, EPSS threshold, secrets), so you aren't paged again for things you already know about.
- **Prometheus metrics** at `/metrics` on the admin port.
- **Trend chart** of daily fleet totals, plus per-image scan history.

## Quick start

```bash
git clone https://github.com/cfunkz/docker-scout-scanner.git
cd docker-scout-scanner
cp .env.example .env          # optional: adjust ports, TLS names, proxies
docker compose up -d --build
docker compose logs scanner | grep "created admin account"
```

1. Open **https://localhost:8443** (or `https://<server-ip>:8443` from your LAN). The certificate is self-signed on first start, so accept it or [use your own](#tls-certificates).
2. Sign in as `admin` with the password from the log. You'll be asked to set a new password (12+ characters).
3. The first scan starts on its own. The vulnerability DB download takes about a minute on first run.

The **admin panel** is at **https://127.0.0.1:8444** and is published on loopback only. From another machine, use an SSH tunnel:

```bash
ssh -L 8444:127.0.0.1:8444 you@docker-host   # then open https://127.0.0.1:8444
```

Lost the password? `docker compose exec scanner scanner reset-password admin`

## Architecture

```
 browser ──HTTPS──▶ nginx (web) ──▶ :8000 dashboard API ─┐
   (LAN / proxy)     :8443 dashboard                      │  scanner (Go, non-root, read-only FS)
                     :8080 → https redirect               │   ├─ SQLite (WAL) in /data
 localhost ─HTTPS──▶ :8444 admin  ──▶ :8001 admin API  ───┤   ├─ SBOM cache  /data/sbom
                                                          │   ├─ trivy / grype (+ their DB caches)
                                                          │   └─ EPSS + CISA KEV feeds
                                                          ▼
                                     docker-socket-proxy (GET-only) ──▶ /var/run/docker.sock (ro)
```

- **scanner**: one static Go binary (about 20 MB of heap when idle) that bundles Trivy and Grype. It has no web assets and is never published to the host.
- **web**: nginx with the static UI (plain JS and CSS, no CDN, no build step). It terminates TLS and proxies `/api`.
- **socket-proxy**: exposes only `GET` on images, containers, events and version. The scanner never sees the real Docker socket, so a bug in a scanner or a parser can't start containers or take over the host.

## Security model

The dashboard is meant to be reachable from your LAN or through a reverse proxy. The admin panel is meant for the host only.

- **Encrypted by default.** nginx serves TLS 1.2/1.3 only (Mozilla intermediate ciphers, no session tickets) and sends HSTS. Plain HTTP on 8080 only redirects.
- **Sign-in required** (this can be turned off in admin settings, with a warning). Passwords use bcrypt (cost 12), with a minimum of 12 characters. The first-run password is random and must be changed. Accounts lock after repeated failures, and nginx rate-limits the login endpoint per IP.
- **Sessions:** 256-bit random tokens, stored only as SHA-256 hashes. Cookies are `__Host-` prefixed, `Secure`, `HttpOnly` and `SameSite=Strict`. Expiry slides and is enforced on the server. Admin sessions are capped at 8 h. Changing a password signs out your other sessions. Admins can see and revoke any session.
- **CSRF:** each session has its own token, sent in a header on every state-changing request. Fetch-Metadata blocks cross-site requests.
- **Admin isolation.** The admin API is a separate listener. The dashboard listener doesn't even have the routes, so a reverse proxy pointed at the dashboard can never reach them. The admin port is published on `127.0.0.1` only, and its sessions use a separate cookie that only admin accounts can get. You can add an extra allow-list with `ADMIN_ALLOW`.
- **Browser hardening:** a strict CSP (`default-src 'none'`, scripts and styles from self only, no inline code), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP, and `noindex`. All advisory text is rendered with `textContent`, and links are restricted to http(s).
- **Least privilege.** The scanner runs as UID 10001 with a read-only root filesystem, all capabilities dropped and `no-new-privileges`. nginx keeps only the capabilities it needs to drop to its worker user. Containers talk over internal networks, and only the scanner has internet egress (for DB updates).
- **Audit log** of sign-ins, failures, setting changes, rules, user changes and purges, with the real client IP.
- **No telemetry.** Trivy telemetry and version checks are disabled. Offline mode makes no network calls at all.

## Running behind a reverse proxy

Point your proxy at `https://<host>:8443`. Tell the stack which proxy IPs to trust, so the audit log and rate limits see real client addresses:

```dotenv
# .env
TRUSTED_PROXIES=10.0.0.5            # or a CIDR such as 172.16.0.0/12
DASHBOARD_BIND=127.0.0.1            # if the proxy runs on the same host
```

Only the listed proxies can set `X-Forwarded-For`. Everyone else's header is ignored.

**Caddy**

```caddy
scanner.example.lan {
    reverse_proxy https://127.0.0.1:8443 {
        transport http { tls_insecure_skip_verify }   # or trust the cert in ./certs
    }
}
```

**Traefik (labels on your proxy network)** works the same way. Use the `https` scheme to port 8443, with `serversTransport.insecureSkipVerify` or a trusted cert.

**Proxy that can only forward plain HTTP?** Set `HTTP_MODE=proxy`. Port 8080 then serves the dashboard without TLS, but **only** to `TRUSTED_PROXIES`. Anyone else gets `403`. Keep `DASHBOARD_BIND` on an address only the proxy can reach.

Sub-paths work too (for example `https://example.lan/scanner/` with the prefix stripped), because the UI uses relative URLs only.

## TLS certificates

On first start the scanner writes a self-signed ECDSA certificate to the `certs` volume, valid for `localhost`, `127.0.0.1`, the container host name and anything in `TLS_SANS`. To use your own certificate (for example from your internal CA or Let's Encrypt), put `cert.pem` (full chain) and `key.pem` in a directory and mount it in place of the volume:

```yaml
# docker-compose.override.yml
services:
  scanner:
    volumes: ["./certs:/certs"]
  web:
    volumes: ["./certs:/certs:ro"]
```

Existing files are never overwritten.

## Configuration

Deployment settings go in `.env`. See [`.env.example`](.env.example), which documents every variable: bind address and ports, TLS names, trusted proxies, the HTTP mode, the first admin account, offline mode, the metrics token and image mirrors.

Everything else lives in the **admin panel → Settings** and applies without a restart:

| Setting | Default | Notes |
|---|---|---|
| Engine | `trivy` | `grype` or `both` (merge and cross-check, shown with a 2× mark) |
| Parallel scans | 2 | 1–16 |
| Full rescan interval | 24 h | Images are also re-matched after every DB update |
| Scan new images on Docker events | on | |
| Only scan images used by containers | off | |
| Exclude patterns | none | Globs such as `k8s.gcr.io/*`, or `<untagged>` |
| Secret scanning | off | Reads every file, only when an image changes |
| DB update interval | 12 h | |
| EPSS / KEV | on | Feed URLs can be changed for mirrors |
| Offline mode | off | Mount DBs into `/data/cache/{trivy,grype}` yourself |
| Scan history kept in full | 10 per image | Older scans keep their counts for trends |
| Webhook | none | `generic`, `slack`, `discord` or `ntfy` |
| Alert on | new CRITICAL, new KEV | Plus an optional EPSS threshold |
| Require sign-in | on | |
| Session lifetime, lockout | 12 h, 5 tries / 15 min | |

The dashboard's **Settings** page holds per-browser display preferences (theme, default filters, page size, auto-refresh), your password, a read-only view of the server configuration, and the list of accepted risks.

## API

Everything the UI shows is JSON under `/api/` and uses the same session cookie. For example: `GET /api/overview`, `/api/images`, `/api/images/{id}/findings`, `/fixplan`, `/diff`, `/export?format=csv|json|sarif|sbom`, `/api/vulns?q=`, `/api/vulns/{CVE}`, `/api/vex`, `/api/trend`.

Admin endpoints live under `/api/admin/` on the admin port only.

Prometheus can scrape `https://127.0.0.1:8444/metrics` with `Authorization: Bearer $METRICS_TOKEN`.

## Operations

- **Backup:** the `scanner-data` volume holds the database, SBOMs and DB caches. `docker run --rm -v docker-scanner_scanner-data:/d -v $PWD:/b alpine tar czf /b/scanner-backup.tgz -C /d .`
- **Update:** `git pull && docker compose up -d --build`. The schema migrates itself.
- **Docker Hub rate limits while building?** Set the `*_IMAGE` variables in `.env` to a mirror, for example `mirror.gcr.io/library/nginx:alpine`.
- **Disk:** SBOMs are typically 10–200 KB per image, gzipped. *Admin → Status → Maintenance* can drop images that were removed from the host, prune history, clear cached SBOMs or compact the DB.
- **Logs:** `docker compose logs -f scanner` (structured key=value lines). Set `LOG_LEVEL=debug` for more detail.

## Development

```bash
cd backend && go test ./...      # unit + HTTP auth-flow tests
go run ./cmd/scanner             # needs trivy on PATH and DATA_DIR / CERT_DIR / DOCKER_HOST set
```

The UI is in `web/`: plain ES modules with no build step. Edit the files and reload the page.
