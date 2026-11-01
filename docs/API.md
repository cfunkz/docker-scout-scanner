# API

Everything the web UI shows comes from a JSON API under `/api/`. You can use it from scripts, dashboards such as Homepage or Home Assistant, and CI.

## Authentication

Create a token in the dashboard under **Settings → API tokens** (or in the admin panel under **My account**). It's shown once. Send it as a bearer token:

```bash
TOKEN=dss_...
curl -k -H "Authorization: Bearer $TOKEN" https://192.168.1.15:8443/api/overview
```

`-k` skips certificate checks for the self-signed certificate. Use `--cacert` with the generated `cert.pem` instead if you prefer.

| Token access | Dashboard port (8443) | Admin port (8444, localhost) |
|---|---|---|
| read only | all `GET` endpoints below | all `GET` endpoints except `/api/admin/*` |
| admin | all `GET` endpoints below | everything, including changes |

A few more rules:

- A token acts as the user who created it. If that user is demoted from admin, their admin tokens lose admin rights at once.
- Tokens can't change passwords, two-factor settings or other tokens.
- Tokens can expire (30 days, 90 days, 1 year or never). Admins see every token and can revoke any of them under **Users**.
- Only a hash of the token is stored. A lost token can't be recovered: delete it and make a new one.

The browser UI uses a session cookie instead, plus an `X-CSRF-Token` header on changes. Scripts should use tokens.

Errors come back as `{"error": "message"}` with a matching HTTP status: 401 for a missing or bad token, 403 for not allowed, 404 for not found, and 429 if you're rate-limited.

## Image IDs

`{id}` is an image ID from `/api/images`: the full `sha256:...` form, the 64 hex characters without the prefix, or the short 12-character form.

## Read endpoints

These work on both ports.

| Endpoint | Returns |
|---|---|
| `GET /api/overview` | Totals (`images`, `critical`, `high`, `kev`, `fixable`, `new_findings`, `eosl` and more), `top_images` and `top_vulns` |
| `GET /api/images` | All images on the host with their latest scan summary. Add `?all=1` to include removed images |
| `GET /api/images/{id}` | One image with its scan history |
| `GET /api/images/{id}/findings` | Findings of the latest scan. `?scan=<scan id>` for an older one |
| `GET /api/images/{id}/fixplan` | Package upgrades ranked by the risk they remove |
| `GET /api/images/{id}/diff` | `new` and `resolved` findings against the previous scan |
| `GET /api/images/{id}/export?format=csv` | Download as `csv`, `json`, `sarif` or `sbom` (CycloneDX) |
| `GET /api/vulns` | One row per vulnerability across all images. `?q=` searches IDs and packages, `?limit=` (default 500) |
| `GET /api/vulns/{CVE}` | One vulnerability and every image that has it |
| `GET /api/trend` | Daily totals for the chart. `?days=` (default 90) |
| `GET /api/ignores` | Accepted-risk rules |
| `GET /api/vex` | Accepted risks as an OpenVEX document |
| `GET /api/settings/public` | Scanner settings that every user can see |
| `GET /api/health` | `{"status":"ok"}`, no sign-in needed |

## Admin endpoints

Only on the admin port (`https://127.0.0.1:8444`), and only for admin users or admin tokens.

| Endpoint | Does |
|---|---|
| `GET /api/admin/status` | Engine and database status, background tasks, queue, version |
| `GET /api/admin/jobs` | Recent scan jobs |
| `POST /api/admin/scan` | `{"all": true}` scans everything, `{"image_id": "..."}` scans one image. Add `"force": true` to re-read images instead of using the cached SBOM |
| `POST /api/admin/sync` | Re-read the image and container list from Docker |
| `POST /api/admin/db/update` | Update the vulnerability databases now |
| `POST /api/admin/intel/update` | Refresh EPSS and KEV now |
| `GET /api/admin/settings` | All settings |
| `PUT /api/admin/settings` | Save settings (send the full object from `GET`) |
| `POST /api/admin/ignores` | Add an accepted-risk rule |
| `DELETE /api/admin/ignores/{id}` | Remove a rule |
| `GET /api/admin/users` | Users, including whether two-factor is on |
| `POST /api/admin/users` | `{"username", "password", "role"}`. Leave `password` empty to generate one |
| `PATCH /api/admin/users/{id}` | `{"role"}`, `{"reset_password": true}`, `{"reset_2fa": true}` or `{"unlock": true}` |
| `DELETE /api/admin/users/{id}` | Delete a user |
| `GET /api/admin/sessions` | Signed-in sessions |
| `DELETE /api/admin/sessions/{id}` | Sign a session out |
| `GET /api/admin/tokens` | API tokens of all users |
| `DELETE /api/admin/tokens/{id}` | Revoke a token |
| `GET /api/admin/audit?limit=200` | Audit log |
| `POST /api/admin/notify/test` | Send a test webhook |
| `POST /api/admin/purge` | `{"what": "absent" \| "history" \| "sboms" \| "vacuum"}` |
| `GET /metrics` | Prometheus metrics |

## Prometheus

Scrape the admin port with either an admin token or the `METRICS_TOKEN` from `.env`:

```yaml
scrape_configs:
  - job_name: docker-scanner
    scheme: https
    tls_config: { insecure_skip_verify: true }
    authorization: { credentials: dss_... }
    static_configs: [{ targets: ["127.0.0.1:8444"] }]
```

## Examples

Fail a CI job if any image has a vulnerability on the KEV list:

```bash
curl -sk -H "Authorization: Bearer $TOKEN" https://scanner.lan:8443/api/overview \
  | jq -e '.kev == 0' > /dev/null || { echo "known-exploited vulnerability found"; exit 1; }
```

Rescan everything after a `docker compose pull` (admin token, run on the server):

```bash
curl -sk -X POST -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"all": true}' https://127.0.0.1:8444/api/admin/scan
```
