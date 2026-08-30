# Reference: Common Developer Actions

## Common commands

| Command                                       | What it does                                                      |
| --------------------------------------------- | ----------------------------------------------------------------- |
| `npm run dev`                                 | Start the dev server on `localhost:8080` with hot-reload          |
| `npm run build`                               | Compile TypeScript to `dist/`                                     |
| `npm test`                                    | Run all tests                                                     |
| `npm run test:unit`                           | Unit tests only (fast, no DB)                                     |
| `npm run test:integration`                    | DB integration tests (requires Postgres)                          |
| `npm run migrate`                             | Apply pending SQL migrations                                      |
| `npm run db:reset`                            | Wipe and recreate the local schema (asks for confirmation)        |
| `npm run validate`                            | Dry-run all `packages/*.toml` configs against real upstream APIs  |
| `npm run validate -- packages/walrus-uv.toml` | Dry-run a single package config                                   |
| `npm run validate -- --online <file>`         | As above, plus a CPE dictionary probe of each pair against NVD    |
| `npm run fmt`                                 | Format source files                                               |
| `npm run fmt:check`                           | Check formatting without writing                                  |
| `npm run lint`                                | Run eslint + oxlint                                               |
| `npm run check-schemas`                       | Validate TOML package configs against the Zod schema (no network) |

---

## Database

### Connecting locally

```bash
psql -U walrus -d walrus
```

Or via the `DATABASE_URL`:

```bash
psql postgresql://walrus:yourpassword@localhost:5432/walrus
```

### Useful queries

```sql
-- What packages are registered?
SELECT name, enabled FROM packages;

-- What versions are known for a package?
SELECT version, version_group, is_lts, version_sort
FROM versions
WHERE package_name = 'uv'
ORDER BY version_sort DESC;

-- Artifact status breakdown for a package
SELECT v.version, a.os, a.arch, a.status, a.error_message
FROM artifacts a
JOIN versions v ON v.id = a.version_id
WHERE v.package_name = 'uv'
ORDER BY v.version_sort DESC;

-- Artifact status breakdown for a package for a particular OS and CPU Arch
SELECT v.version, a.os, a.arch, a.status, a.error_message
FROM artifacts a
JOIN versions v ON v.id = a.version_id
WHERE v.package_name = 'uv' and a.os = 'linux' and a.arch = 'x86-64'
ORDER BY v.version_sort DESC;

-- Recent sync jobs
SELECT id, package_name, trigger_type, status, versions_found,
       artifacts_queued, artifacts_downloaded, artifacts_failed,
       started_at, completed_at
FROM sync_jobs
ORDER BY started_at DESC
LIMIT 20;

-- Failed artifacts
SELECT v.package_name, v.version, a.os, a.arch, a.error_message
FROM artifacts a
JOIN versions v ON v.id = a.version_id
WHERE a.status = 'failed'
ORDER BY a.download_completed_at DESC;
```

### Running migrations

```bash
npm run migrate
```

Migration files live in `src/db/migrations/` and are numbered `0001_`, `0002_`, etc. The migration runner (`postgres-migrations`) is idempotent — re-running is safe.

### Resetting the database (destructive)

```bash
npm run db:reset
```

This will prompt for confirmation, then drop and recreate the `public` schema and re-run all migrations. Use this to get back to a clean state during development.

---

## Running the project locally

### Dev server

```bash
npm run dev
```

Starts on `http://localhost:8080` with `tsx watch` (hot-reload on file changes). Migrations run automatically on startup. Artifacts are stored under `./data/artifacts/` (local filesystem backend).

### Health check

```bash
curl http://localhost:8080/health
# {"isAvailable":true,"gitUrl":"https://github.com/pdvcs/walrus","ts":"...","started":"...","inGracePeriod":true,"version":"0.2.0"}

curl http://localhost:8080/app/status
# The health fields plus vulnerability freshness, sync status, and degradations.
```

`/app/health` is an alias of `/health`. PostgreSQL failures make the application unavailable
after the 300-second startup grace period; operational degradations remain available separately
under `/app/status` and do not fail the deployment health check. PostgreSQL probe results,
including failures, are cached for 60 seconds across all three paths.

### API documentation and OpenAPI spec

Two endpoints are always available once the server is running:

| URL                                  | What it returns                                                   |
| ------------------------------------ | ----------------------------------------------------------------- |
| `http://localhost:8080/api`          | Human-readable API docs (HTML in browser, raw Markdown otherwise) |
| `http://localhost:8080/openapi.json` | OpenAPI 3.1.0 specification (machine-readable)                    |

The OpenAPI spec is generated at startup from Zod schemas — it is never hand-edited. See [API schema architecture](#api-schema-architecture) below.

---

## Common development scenarios

These show how to exercise the full pipeline from discovery through to download. Run these against a local dev server (`npm run dev`).

### Operator login and API tokens

Set a local password of at least 16 bytes in gitignored `.env.secrets`:

```dotenv
WALRUS_ADMIN_PASSWORD=<your-local-password>
```

Browse to `http://localhost:8080/`, choose **Log in as admin**, and use `admin` with that password.
Successful browser login opens `/admin/v1/`. The admin navigation exposes **API token**, which
mints a new bearer credential and displays it once, and **Log out**, which clears the browser
cookie. Browser sessions use an HttpOnly cookie scoped to `/admin/v1`. For curl, prompt without
putting the password in shell history, request a non-renewing bearer credential, and then unset it:

```bash
read -rsp 'Walrus admin password: ' WALRUS_LOGIN_PASSWORD; echo
export WALRUS_ADMIN_TOKEN="$(curl -fsS http://localhost:8080/admin/v1/login \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -nc --arg password "$WALRUS_LOGIN_PASSWORD" \
    '{username:"admin", password:$password}')" | jq -r .token)"
unset WALRUS_LOGIN_PASSWORD
alias walrus-admin-curl='curl -H "Authorization: Bearer ${WALRUS_ADMIN_TOKEN}"'
```

Production has no auth-disable switch. It requires `WALRUS_ADMIN_PASSWORD`, a session secret of at
least 32 bytes, a non-empty `config/admins.toml`, and the internal OIDC audience/principal settings.
Session-key rotation accepts `WALRUS_SESSION_SECRET_PREVIOUS`; raise `WALRUS_SESSION_EPOCH` for a
global logout. Browser cookies are HttpOnly, SameSite=Lax, Secure in production, and scoped to
`/admin/v1`; they renew after half the two-hour TTL but never beyond the eight-hour login cap.
Bearer tokens never renew. Logout only clears the browser cookie because sessions are stateless;
remove the subject from the roster on redeploy or raise the epoch when revocation cannot wait for
expiry.

Adopters can set `WALRUS_AUTHN_PROVIDER=/app/ext/directory-authn.js` to load one external provider.
The module exports an `AuthnProvider` (`apiVersion: 1`); its optional Zod `configSchema` receives the
whole environment and `init()` runs during boot. A provider returning `unavailable` never falls
back to the password provider. Deliver the compiled module and reviewed roster in a downstream
image:

```dockerfile
FROM ghcr.io/example/walrus:0.3.0
COPY ext /app/ext
COPY config/admins.toml /app/config/admins.toml
ENV WALRUS_AUTHN_PROVIDER=/app/ext/directory-authn.js
```

### 1. Trigger a sync and watch it run

Start a sync for a single package:

```bash
curl -s -X POST http://localhost:8080/admin/v1/sync/uv | jq .
```

This returns a `job_id` immediately (HTTP 202). Track progress:

```bash
# JSON
curl -s http://localhost:8080/admin/v1/jobs/1 | jq '.status, .artifacts_downloaded, .artifacts_failed'

# Browser-friendly live view (auto-refreshes while running)
open http://localhost:8080/admin/v1/jobs/1
```

The job status page polls automatically every 2 seconds while the job is running.

### 2. Dry-run a sync (no DB or storage writes)

```bash
curl -s -X POST "http://localhost:8080/admin/v1/sync/uv?dry_run=true" | jq .
```

Returns the versions that would be discovered and artifacts that would be queued, without writing anything.

### 3. Query what's available after a sync

List all packages:

```bash
curl -s http://localhost:8080/api/v1/packages | jq -r '.packages[].name'
```

List versions for a package (with platform availability):

```bash
curl -s http://localhost:8080/api/v1/packages/uv/versions | jq .
```

Get the latest version in a release group:

```bash
curl -s "http://localhost:8080/api/v1/packages/uv/versions/0.9/latest?os=macos&arch=arm64" | jq .
```

This is the endpoint a package manager server needs to call to build a recipe. The response includes the download URL, checksum, and file size.

### 4. Download a binary

Once an artifact is `available`, download it:

```bash
curl -OJ http://localhost:8080/download/uv/0.9.30/linux/x86-64
```

The `-J` flag uses the server-provided `Content-Disposition` filename. The response also sets `X-Checksum-Sha256` on the header.

### 5. Validate a package config before committing

```bash
npm run validate -- packages/walrus-uv.toml
```

This makes real upstream API calls to verify the TOML config is correct — the discovery strategy finds versions, the artifact URL resolves, and a HEAD request confirms the binary is accessible. Nothing is written to the database or storage.

### 6. Re-download a failed artifact

```bash
# Find failures
curl -s http://localhost:8080/admin/v1/artifacts/failed | jq .

# Find pending items
curl -s http://localhost:8080/admin/v1/artifacts/pending | jq .

# Re-trigger a specific artifact
curl -s -X POST http://localhost:8080/admin/v1/redownload/uv/0.9.30/linux/x86-64 | jq .
```

### 7. Sync all packages

```bash
curl -s -X POST http://localhost:8080/admin/v1/sync | jq .
```

Returns a list of `job_id`s, one per package. Each can be tracked individually.

### 8. Bootstrap vulnerability data from an empty database

No manual package or CPE inserts are required. On startup, Walrus applies every database migration
and reconciles the `[vulnerabilities]` sections from `packages/*.toml` into `packages`,
`package_cpes`, and `package_aliases`. The HTTP server does not begin listening until that bootstrap
has completed.

For a new production deployment:

1. Deploy Walrus and wait for the service health check to succeed:

   ```bash
   export WALRUS_URL="https://<walrus-cloud-run-service-url>"
   curl -fsS "$WALRUS_URL/health" | jq .
   ```

2. Start the full-history NVD backfill:

   ```bash
   curl -fsS -X POST "$WALRUS_URL/admin/v1/vuln-backfill" \
     -H "Authorization: Bearer $WALRUS_ADMIN_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{}' | tee /tmp/walrus-backfill.json | jq .
   ```

   The response is `202 Accepted` and includes a durable job ID and `status_url`. The request only
   launches the dedicated Cloud Run Job; it does not wait for the backfill to finish.

3. Poll the returned status URL until the job reaches `succeeded` or `failed`:

   ```bash
   STATUS_URL=$(jq -r '.status_url' /tmp/walrus-backfill.json)
   curl -fsS "$WALRUS_URL$STATUS_URL" \
     -H "Authorization: Bearer $WALRUS_ADMIN_TOKEN" | jq '.job | {
     status, cpe_pairs_done, cpe_pairs_total, started_at, finished_at, error_message
   }'
   ```

The Cloud Run Job defensively runs migrations and package/CPE reconciliation again before it reads
the configured CPE pairs. This makes the job safe to launch immediately after the first healthy
service startup, including when the database was initially empty. An empty `cpe_pairs_total` after
startup means no valid `[vulnerabilities].cpes` entries were loaded; inspect the service startup
logs before retrying.

For local development, the same HTTP endpoint runs the durable job asynchronously inside the local
Walrus process; no GCP credentials are required. Start `npm run dev`, submit the same POST request
against `http://localhost:8080`, and poll its returned status URL. Keep that dev process running
until the job finishes. The development-only CLI remains available for lower-level debugging, but
is not required for this workflow:

```bash
npm run vuln:backfill
# Or limit history:
npm run vuln:backfill -- --since 2015-01-01
```

### 9. Suppress a mis-attributed CVE

Use the vulnerability explorer at `/admin/v1/vulns?product=<package>&version=<version>`. A gating
CVE has a **Suppress** action; an active assertion stays visible with its reason and a **Revoke**
action. The UI requires a preview of the exact fields before apply and shows every cached version
that would become available or blocked.

This is a production action, not a CLI/database procedure (ADR-004/ADR-007). Complete the team's
six-eyes review and formal approval first. The operator identity and non-empty reason are required
and stored in `admin_actions`; create and revoke use distinct action types.

API clients use the same handlers:

```bash
# Preview (no write)
curl -sS -X POST "$WALRUS_URL/admin/v1/vuln-suppressions/preview" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $WALRUS_ADMIN_TOKEN" \
  -d '{"cve_id":"CVE-2099-0001","package_name":"openjdk","reason":"Confirmed mis-attribution"}' | jq .

# Apply the approved package-scoped assertion
curl -sS -X POST "$WALRUS_URL/admin/v1/vuln-suppressions" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $WALRUS_ADMIN_TOKEN" \
  -d '{"cve_id":"CVE-2099-0001","package_name":"openjdk","reason":"Confirmed mis-attribution"}' | jq .

# Preview revocation, then apply it with the same body
curl -sS -X POST "$WALRUS_URL/admin/v1/vuln-suppressions/42/revoke/preview" \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $WALRUS_ADMIN_TOKEN" \
  -d '{"reason":"Upstream attribution corrected"}' | jq .

# Inspect the create/revoke audit trail; optionally filter by cve_id
curl -sS "$WALRUS_URL/admin/v1/vuln-suppressions/audit?limit=50" | jq .
```

Omit `package_name` only for an explicitly approved CVE-wide assertion. Optional `expires_at`
must be a future ISO-8601 timestamp; once it passes, the CVE gates again on read without a job.
Audit responses are newest-first. Pass the returned `next_before_id` as `before_id` to fetch the
next page; `limit` defaults to 50 and is capped at 100.

---

## API schema architecture

All JSON response shapes for the public API are defined as Zod schemas in a single file:

```
src/routes/schemas.ts
```

These schemas are the **single source of truth** for both:

1. **Runtime validation** — each route calls `Schema.parse(payload)` before calling `res.json()`. If a code change produces a response that doesn't match its schema, the server throws a 500 at runtime (caught immediately in dev or tests).
2. **OpenAPI spec generation** — `src/routes/openapi.ts` registers every path against these schemas using `@asteasolutions/zod-to-openapi`. The `/openapi.json` endpoint serves the generated document. There is no hand-written spec.

The consequence is that `src/routes/schemas.ts` and `src/routes/packages.ts` are always in sync — changing a field name in the schema causes a TypeScript error in the route that constructs that response. The OpenAPI spec updates automatically on the next server start.

`api-docs.md` (the human-readable docs served at `/api`) is kept in sync manually. It is intended to be refreshed periodically; it carries examples and prose that can't be auto-generated.

### Zod version

The project uses **Zod v4** (`zod@^4`) alongside `@asteasolutions/zod-to-openapi@^8`, which requires Zod v4.

---

## Adding a new package

1. Create `packages/<name>.toml` following the schema in `docs/DESIGN.md` (or `walrus-ingress.md` §2 for the full reference with all fields).
2. Run `npm run validate -- packages/<name>.toml` to confirm discovery and artifact URLs work.
3. That's it — no code changes needed.

Discovery strategy selection order (use the highest that applies):

1. `github-releases` — GitHub Releases API
2. `json-api` — generic JSON API with JSONPath (two-step or inline)
3. `directory-listing` — filename pattern matching on a directory listing
4. `html-scrape` — regex extraction from HTML (last resort; not implemented yet)

---

## Environment variable reference

| Variable               | Dev default                                     | Description                                   |
| ---------------------- | ----------------------------------------------- | --------------------------------------------- |
| `DATABASE_URL`         | `postgresql://walrus:...@localhost:5432/walrus` | Postgres connection string                    |
| `STORAGE_BACKEND`      | `local`                                         | `local` or `gcs`                              |
| `LOCAL_STORAGE_PATH`   | `./data/artifacts`                              | Root dir for local storage backend            |
| `PORT`                 | `8080`                                          | HTTP listen port                              |
| `NODE_ENV`             | `development`                                   | `development` or `production`                 |
| `LOG_LEVEL`            | `debug`                                         | `debug`, `info`, `warn`, `error`              |
| `SYNC_CONCURRENCY`     | `4`                                             | Parallel package syncs                        |
| `DOWNLOAD_CONCURRENCY` | `2`                                             | Parallel downloads per package                |
| `DEFAULT_RETENTION`    | `3`                                             | Default `versions_per_group` if unset in TOML |
| `GCS_BUCKET`           | —                                               | GCS bucket name (prod only)                   |
| `GCP_PROJECT`          | —                                               | GCP project ID (prod only)                    |
