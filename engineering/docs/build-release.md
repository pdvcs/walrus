# Build and Release

## Prerequisites

- **Node.js** 24+
- **npm** (comes with Node)
- **PostgreSQL** installed locally — no Docker needed; the dev setup talks to a native Postgres instance directly

## Setting up a local dev environment

### 1. Install dependencies

```bash
npm install
```

### 2. Create the local database

Run once:

```bash
createdb walrus
createuser walrus
psql -c "ALTER USER walrus WITH PASSWORD 'yourpassword';"
psql -c "GRANT ALL ON SCHEMA public TO walrus;" walrus
```

### 3. Configure environment files

Two files are needed. **`.env.local`** is committed to the repo with safe defaults:

```
DATABASE_URL=postgresql://walrus:${WALRUS_DEV_DB_PASSWORD}@localhost:5432/walrus
STORAGE_BACKEND=local
LOCAL_STORAGE_PATH=./data/artifacts
PORT=8080
NODE_ENV=development
LOG_LEVEL=debug
```

**`.env.secrets`** is _not_ committed — create it in the repo root with your actual DB password:

```
WALRUS_DEV_DB_PASSWORD=yourpassword
```

Both files are loaded together by any `npm run` script that needs database access (`migrate`, `test:integration`, `dev`). You only need `.env.local` for commands that don't touch the database (e.g. `validate`).

### 4. Run migrations

```bash
npm run migrate
```

This applies any pending migration files from `src/db/migrations/`. On a fresh database this creates the five tables: `packages`, `versions`, `artifacts`, `sync_jobs`, `admin_actions`.

The server also runs migrations automatically on `npm run dev` startup via `runMigrations()` in `src/db/client.ts`.

---

## Building

```bash
npm run build
```

Compiles TypeScript to `dist/` via `tsc`. The compiled output targets CommonJS / ES2022. The `main` entrypoint is `dist/main.js`.

---

## Testing

### Unit tests (no database or network required)

```bash
npm run test:unit
```

Runs tests under `tests/common/`, `tests/discovery/`, `tests/services/`, `tests/routes/`, and `tests/storage/`. These use `vitest` with `msw` to mock HTTP and do not require a database connection or real upstream API access.

### Integration tests (require a dedicated `walrus_test` database)

```bash
createdb walrus_test   # one-time
npm run test:integration
```

Integration tests under `tests/db/` (and the DB-backed route tests) perform destructive
writes and **global** cleanups, so they run against a **separate throwaway database**, never
the dev/prod `walrus` DB. `vitest.config.ts` forces `DATABASE_URL` to
`postgresql://walrus:walrus@localhost:5432/walrus_test` (override with `TEST_DATABASE_URL`),
and `tests/setup.ts` **hard-fails the whole run** if the target database name does not end in
`_test` — the safety net that prevents `npm test` from ever wiping real data. Migrations run
automatically in each test file's setup, so a freshly-created empty `walrus_test` is enough.

### All tests

```bash
npm test
```

Runs both unit and integration test suites.

### Watch mode (during development)

```bash
npx vitest
```

Runs in watch mode, re-running affected tests on file changes.

### Release testing

_Not yet implemented._

---

## Releasing

_Not yet implemented._

---

## Vulnerability data — ops runbook

Walrus ingests CVE data for the packages that declare a `[vulnerabilities]` section (see
[package-config.md](package-config.md)). There is **no resident worker** — ingestion runs on
external cron hitting `/internal` endpoints, plus a one-time backfill.

### 1. Secrets

Add an NVD API key to `.env.secrets` (gitignored). It is an _upstream_ credential only —
unrelated to walrus authn — and raises the NVD rate limit from 5 to 50 requests / 30s, which
makes the backfill tolerable:

```bash
# .env.secrets
WALRUS_DEV_DB_PASSWORD=…
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx   # request one at https://nvd.nist.gov/developers/request-an-api-key
```

Keyless operation works but is ~10× slower; the backfill will still complete.

### 2. One-time backfill

Populate historical CVEs for every configured CPE pair. Run once after first deploy (or after
adding new packages/CPEs):

```bash
npm run vuln:backfill                        # full history for all CPE pairs
npm run vuln:backfill -- --since 2015-01-01  # limit to CVEs published on/after a date
```

The script pages the NVD `virtualMatchString` API per CPE pair, writes `cves` + `cve_affects`,
and advances the `nvd-cve` cursor. Verify:

```sql
SELECT count(*) FROM cve_affects ca JOIN packages p ON p.name = ca.package_name WHERE p.name = 'openjdk';
```

### 3. Cron cadence (incremental)

Point your scheduler (Cloud Scheduler, k8s CronJob, …) at the `/internal` triggers. Suggested
cadence — NVD changes often, KEV daily, OSV is a weekly cross-check:

| Source | Endpoint                       | Cadence                                                            |
| ------ | ------------------------------ | ------------------------------------------------------------------ |
| NVD    | `POST /internal/vuln-sync/nvd` | 2-hourly                                                           |
| KEV    | `POST /internal/vuln-sync/kev` | daily                                                              |
| OSV    | `POST /internal/vuln-sync/osv` | weekly                                                             |
| all    | `POST /internal/vuln-sync/all` | (nvd → kev → osv in one call; continues past a per-source failure) |

Each call returns per-source outcomes (`200` all-ok, `207` if any source failed). Incremental
NVD sync reads/writes the `lastModStartDate` cursor in `vuln_sync_state`; the cursor only
advances on success, so a failed run retries the same window next time. On a fresh DB (no
cursor) an incremental run bootstraps a 119-day lookback — run the backfill for full history.

Operators can also trigger a sync from the admin UI (`/admin/v1/vulns` → "Sync … now"), which is
recorded in `admin_actions`.

### Data-source attribution

- **NVD** — This product uses data from the NVD API but is not endorsed or certified by the NVD.
- **CISA KEV** — Known Exploited Vulnerabilities Catalog, CISA (public domain).
- **OSV** — osv.dev, Google (Apache-2.0).

---
