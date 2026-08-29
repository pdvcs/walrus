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
curl -X POST "$WALRUS_URL/internal/vuln-backfill" -H 'Content-Type: application/json' -d '{}'
curl -X POST "$WALRUS_URL/internal/vuln-backfill" -H 'Content-Type: application/json' -d '{"since":"2015-01-01"}'
```

The dated form sends paired `pubStartDate`/`pubEndDate` parameters in adjacent windows no longer
than the NVD API's 120-day maximum. Invalid, impossible, and future dates are rejected before the
backfill starts.

Removing a CPE pair or OSV mapping from a package's TOML deletes the derived `cve_affects` rows at
the next boot reconciliation. Re-adding a previously removed CPE pair therefore requires re-running
`npm run vuln:backfill` to restore its historical NVD associations (incremental sync only covers
recently modified CVEs).

Production requests return `202 Accepted` immediately with a durable job and `status_url`. Poll
that URL for `queued`, `running`, `succeeded`, or `failed`; progress is reported as
`cpe_pairs_done` / `cpe_pairs_total`. A concurrent NVD backfill returns `409 already_running`.
The API launches the dedicated `walrus-vuln-backfill` Cloud Run Job, whose 24-hour task timeout
avoids the serving service's 3,600-second request deadline. The keyless NVD limit makes a full
history run potentially take hours; configure `NVD_API_KEY` in production. The local
`npm run vuln:backfill` command remains available for development only and shares the ingestion
implementation with the job runner.

The job pages the NVD `virtualMatchString` API per CPE pair, writes `cves` + `cve_affects`, and
advances the `nvd-cve` cursor. Verify:

```sql
SELECT count(*) FROM cve_affects ca JOIN packages p ON p.name = ca.package_name WHERE p.name = 'openjdk';
```

### 3. Cron cadence (incremental)

On GCP these are provisioned by Terraform (`infra/terraform/scheduler.tf`) as one Cloud Scheduler
job per source, authenticating with the same service account as the package sync. Cadence —
NVD changes often, KEV daily, OSV is a weekly cross-check — is set by variable, so overriding one
source does not touch the others:

| Job                     | Variable                  | Default        |
| ----------------------- | ------------------------- | -------------- |
| `walrus-vuln-sync-nvd`  | `vuln_sync_nvd_schedule`  | `20 */2 * * *` |
| `walrus-vuln-sync-kev`  | `vuln_sync_kev_schedule`  | `40 7 * * *`   |
| `walrus-vuln-sync-osv`  | `vuln_sync_osv_schedule`  | `10 8 * * 1`   |
| `walrus-vuln-sync-cvss` | `vuln_sync_cvss_schedule` | `10 9 * * *`   |

Minutes are offset from the package sync (minute 0) and from each other, since `nvd` and `cvss`
share one advisory lock and a contended run is wasted work.

Note the package sync is not one of these: it runs as the `walrus-sync` **Cloud Run Job**,
executed directly by Cloud Scheduler rather than triggered over HTTP. Artifact downloads run
to hundreds of MB and outlast any request deadline, so the work belongs in its own container
(ADR-004). Each package also takes a per-package advisory lock, so an overlapping trigger
skips that package rather than racing it — visible as `skipped: "already_running"` in the
response from `/internal/sync`, or `409` when a single package is requested.

`cvss` **is** scheduled, by PO decision — see ADR-002. Enrichment can newly satisfy the

> = 9.0 download gate, turning versions that serve today into 403s; here that is the intended
> behaviour rather than a hazard to gate behind a human. Safety outweighs availability, and
> "we err on the side of denial once a CVE scores above the limit" is a policy that can be stated
> to compliance. It stays excluded from `/vuln-sync/all` so routine ingestion stays fast — the job
> triggers the source directly.

One consequence to hold in mind: a consumer's download can start failing on walrus's schedule
rather than on any change they made. `/api/v1/packages/:name/vulns` shows which CVE is
responsible, and `/admin/v1/vulns` → CVSS enrichment (or `dry_run` on the API) previews what a
run would block before it runs.

Every `/internal/vuln-sync/:source` trigger — success or failure — is written to `admin_actions`
with `performed_by = 'internal'`, so an unattended gate change is distinguishable from an
operator's click, which leaves `performed_by` null:

```sql
SELECT created_at, coalesce(performed_by, 'admin UI') AS by, details
FROM admin_actions WHERE action_type = 'vuln-sync' ORDER BY id DESC LIMIT 20;
```

The row carries the per-source outcome counts, not the identity of the versions that crossed the
gate — see ADR-002 for that limitation.

Cloud Scheduler's default attempt deadline is 180 seconds, short enough to abandon an incremental
NVD walk mid-flight; the jobs set it explicitly (1,800s is Scheduler's maximum, below the Cloud Run
service's 3,600s, so Scheduler is the binding limit). The NVD job does not retry: its cursor only
advances on success, so the next scheduled run repeats the same window anyway.

Off GCP, point your own scheduler (k8s CronJob, …) at the same `/internal` triggers:

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

Upstream vulnerability requests have a 30-second per-request timeout by default (override with
`VULN_HTTP_TIMEOUT_MS`). A non-blocking PostgreSQL advisory lock permits only one invocation of a
given source across Walrus instances. A direct overlapping trigger returns `409` with
`code: "already_running"`; `all` continues the other sources and returns `207` with the contended
source represented in its outcomes.

The Cloud Run service request timeout is 3,600 seconds. Incremental NVD runs are expected to fit
when an NVD API key is configured, but full backfills do not: even one request per configured CPE
pair at the keyless 4–5 requests/30-second rate, multiplied by pagination and historical date
windows, can exceed an hour. Full backfills therefore always use the asynchronous Cloud Run Job;
the job's 24-hour timeout is the overall watchdog and its database advisory lock prevents overlap.

Freshness timestamps represent the **last successful** source run. `/health` and the admin panel
also expose the latest attempt outcome and failure time, so a failed refresh cannot make stale data
appear current.

The download gate blocks a version on **any** CVSS base score — v3, v4, or v2 — at or above 9.0,
or a score-less CRITICAL severity (`meetsCriticalGate`, ADR-005). KEV (exploited in the wild) is
flagged everywhere but does not block on its own — PO decision, may be revisited.

**Degradation reporting.** `/health` also carries a `degradations` array: per-source staleness
(NVD success older than 12h, KEV 48h, OSV 8 days), sources that are currently failing or have
never succeeded, and stuck or disabled autonomous backfills. `status` stays `"ok"` for these —
it is reserved for major events — so external monitors should watch `degradations` length, not
status. The same list renders as a warning banner across the admin UI, which is currently the
surface an operator sees it on; alerting and email notification are planned on top
(TODO — see ADR-002 Option C).

### 4. After setup: what runs itself, and what does not

Once the one-time backfill in §2 has been done, vulnerability ingestion is autonomous — no
routine operator action is required, including when a package is added.

| Event                                  | Handled by                                   | Autonomous? |
| -------------------------------------- | -------------------------------------------- | ----------- |
| New CVEs published / rescored          | `nvd` incremental, 2-hourly                  | Yes         |
| CVE added to CISA KEV                  | `kev`, daily                                 | Yes         |
| OSV advisory added or changed          | `osv`, weekly (re-queries every pkg)         | Yes         |
| CVE arrives with no severity           | `cvss`, daily                                | Yes         |
| Version passes its cooling-off period  | Next package sync (`walrus-sync` Job)        | Yes         |
| **New package, or new CPE pair added** | **`walrus-vuln-backfill-auto` sweep, daily** | **Yes**     |

That last row is the one that needed building. Incremental NVD sync is cursor-based
(`lastModStartDate`), so it only sees recently-modified CVEs — a newly tracked package's
_historical_ CVEs are structurally unreachable by it, and only a targeted backfill gets them.
The other sources need no equivalent: OSV re-queries every tracked package in full each run,
KEV flags rows in the global `cves` table, and `cvss` walks every severity-less CVE.

The sweep (`POST /internal/vuln-backfill/auto`) compares each package's current CPE set
against the set its last backfill covered, and starts a targeted backfill where they differ.
Comparing the _set_, not a timestamp, is what makes a CPE pair added to an already-covered
package trigger a fresh backfill.

- One at a time: only one backfill may be active, so the rest are reported `deferred` and
  picked up by the next sweep.
- Bounded retries: after three failed attempts a package stops being retried and is named in
  the operator hints instead.
- Contention is not a failure and does not consume the retry budget.
- `VULN_AUTO_BACKFILL=false` disables the sweep without touching scheduled ingestion. While
  disabled, uncovered packages are named in the hints, since nothing else will cover them.

To force one package immediately rather than waiting for the sweep:

```bash
curl -X POST "$WALRUS_URL/internal/vuln-backfill" \
  -H 'Content-Type: application/json' -d '{"package":"<name>"}'
```

### Operator CVE suppressions

When upstream has attributed a CVE to the right CPE shape but the wrong product in fact, use the
admin vulnerability explorer to preview and apply a package-scoped suppression. There is no
production shell or supported manual-SQL path (ADR-004/ADR-007). Complete six-eyes review and formal
approval before applying the change; walrus records the executing operator, reason, scope, expiry,
and suppression ID in `admin_actions`. Revocation is a separate audited action.

Suppression never deletes vulnerability evidence. The CVE remains in public responses marked
suppressed with its reason, while only the download gate ignores it. An optional expiry restores
gating automatically. Active suppressions are counted in `/health.degradations` and the explorer
status strip so the list is regularly revisited.

```bash
# Latest create/revoke audit entries (50 by default, maximum 100)
curl -sS "$WALRUS_URL/admin/v1/vuln-suppressions/audit" | jq .

# One CVE only; use next_before_id from the response for the next page
curl -sS "$WALRUS_URL/admin/v1/vuln-suppressions/audit?cve_id=CVE-2099-0001&limit=20" | jq .
```

### Data-source attribution

- **NVD** — This product uses data from the NVD API but is not endorsed or certified by the NVD.
- **CISA KEV** — Known Exploited Vulnerabilities Catalog, CISA (public domain).
- **OSV** — osv.dev, Google (Apache-2.0).

---

### Removing a package (WAL-53)

Delete its TOML; the next boot reconciliation tombstones it automatically. The row is marked
with `removed_at` and disabled — serving stops (including direct `/download` URLs), syncs stop,
and its vuln config (aliases, CPE pairs, OSV mapping) and derived `cve_affects` rows are
cleared so no ingestion traffic still targets it.

The row, cached versions, artifacts and history are deliberately **kept**: hard delete requires
an explicit admin decision because DB rows own storage objects a stray `git rm` must never
destroy. Re-adding the same TOML revives the package (`removed_at` cleared, enabled again);
its historical NVD associations then need the usual targeted backfill.

A watch-only or operator-disabled package is unaffected: the marker distinguishes an actual
removal from either.

---
