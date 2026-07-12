# Changelog

All notable changes to Walrus are documented here.

## Version 0.2.0: Vulnerability intelligence

Add CVE-lookup capability into walrus, keyed to walrus packages. Also add an admin UI and the ability to cross-reference CVEs against the package versions walrus has cached (i.e. which of the versions walrus is actually serving carry known CVEs).

**Wave 1 — Foundation**

- **WAL-2** Migration `0002_vulnerabilities.sql` (`pg_trgm`, `cves`, `cve_affects` with
  `UNIQUE NULLS NOT DISTINCT` dedupe, `package_cpes`, `package_aliases`, `vuln_sync_state`,
  `unresolved_queries`, `packages.osv_*`) + typed query modules (`cves`, `package-aliases`,
  `vuln-sync-state`).
- **WAL-3** Optional `[vulnerabilities]` TOML section (CPEs, OSV mapping, aliases) with boot
  reconciliation into the DB (config vs. learned aliases preserved); all ten package configs
  annotated; wired into `check-schemas` and `validate`. _(MANUAL_TEST: CPE verification — PO.)_
- **WAL-4** Ported matching core: `normalize`, `version-ranges` (fail-open, property-tested),
  `cpe`.

**Wave 2 — Ingestion (no resident worker)**

- **WAL-6** NVD API 2.0 client — pagination, sliding-window rate limiting, exponential backoff;
  optional `NVD_API_KEY`; msw-fixture tests.
- **WAL-7** NVD sync — incremental (`lastModStartDate` cursor) + `npm run vuln:backfill`;
  `cpeMatch` → `cve_affects` mapping; `POST /internal/vuln-sync/:source`. _(MANUAL_TEST: live
  backfill — PO.)_
- **WAL-8** CISA KEV flagging + OSV cross-check with source provenance; `all` runner continues
  past per-source failures.

**Wave 3 — Query API**

- **WAL-10** Name-resolution pipeline (exact → alias → pg_trgm + fuzzball) with unresolved-query
  logging.
- **WAL-11** `GET /api/v1/vulns` — flagship contract with golden tests (three distinct
  "no result" states, fail-open on uncomparable versions).
- **WAL-12** `GET /api/v1/vulns/products/search`, `GET /api/v1/cves/:cveId`, and
  `vuln_data_freshness` on `/health`.
- **WAL-13** `GET /api/v1/packages/:name/vulns` — cross-reference CVEs against cached versions
  (walrus-native).

**Wave 4 — UI & rollout**

- **WAL-15** Admin vulnerability explorer (`/admin/v1/vulns`) with autocomplete, distinct
  no-result states, data-freshness panel, and audited sync-now buttons; per-version CVE badges on
  package pages. _(MANUAL_TEST: visual — PO.)_
- **WAL-16** API docs, README, design doc, package-config doc, and the ops runbook (secrets →
  backfill → cron cadence); NVD/KEV/OSV attribution and standing disclaimer. Docs moved to `engineering/docs/`.

New deps: `fuzzball`, `semver` (runtime); `fast-check` (dev). `pg_trgm` extension required.

**Wave 6 — Vulnerability remediation**

- **WAL-19 / WAL-20 (Fixed):** OSV refreshes now replace affects per package transactionally, and
  incremental NVD sync rebuilds locally known CVEs whose tracked CPE associations were removed.
- **WAL-21 (Fixed):** dated NVD backfills use paired, adjacent publication windows within the
  120-day API limit and reject invalid or future dates.
- **WAL-22 (Fixed):** vulnerability freshness now reports the last successful sync separately from
  the latest attempt/failure status via migration `0003_vuln_sync_outcomes.sql`.
- **WAL-23 (Added):** `GET /api/v1/vulns/products/:name` returns package vulnerability metadata,
  aliases, CPEs, OSV mapping, tracking state, and a distinct CVE count.
- **WAL-24 (Security):** NVD, KEV, and OSV requests have bounded timeouts; per-source PostgreSQL
  advisory locks reject overlapping syncs with an explicit `already_running` outcome.
- **WAL-25 (Changed):** NVD configuration-tree flattening is documented as a conservative
  applicability limitation and pinned with regression coverage.

**Wave 7 — Review follow-up**

- **WAL-26 (Fixed):** removing a package's OSV mapping or CPE pairs from its TOML config now
  deletes the derived `cve_affects` rows during boot reconciliation, instead of leaving permanent
  false positives no sync path would ever revisit.
- **WAL-26 (Fixed):** `withVulnSyncLock` no longer masks the sync's original error or leaks its
  pool client when advisory unlock fails on a dead connection.
- **WAL-27 (Changed):** long-running production NVD backfills use a dedicated Cloud Run Job with a
  24-hour task timeout; fast incremental NVD/KEV/OSV endpoints remain synchronous within the
  Cloud Run service's 3,600-second request deadline.
- **WAL-28 (Added):** migration `0004_vuln_backfill_jobs.sql` adds durable backfill lifecycle and
  per-CPE-pair progress. `POST /internal/vuln-backfill` and its admin equivalent return `202` with
  a job reference; status is available from `GET /internal/vuln-backfill/:id`, and overlapping
  backfills or incremental NVD syncs return `409`.
- **WAL-28 (Added):** production Terraform provisions the backfill Cloud Run Job and launcher IAM;
  local development uses the same shared backfill service through an in-process asynchronous
  launcher. The CLI remains available for development and shares the orchestration path.
- **WAL-28 (Verified locally):** a clean-database, full-history HTTP backfill completed all 10 CPE
  pairs successfully. GCP Terraform/application and Cloud Run launch validation remain deployment
  gates.

**Wave 8 — Vulnerability-aware serving**

- **WAL-30 (Changed):** `GET /api/v1/packages/:name/versions` now reports a version-level
  `status` of `blocked` for concrete known-critical CVE matches and `available` otherwise,
  using the same gate as the groups endpoint.
- **WAL-31 (Security):** `GET /api/v1/packages/:name/versions/:group/latest` skips blocked
  versions and never returns a download URL when all platform-compatible versions carry a
  known critical CVE.
- **WAL-32 (Security):** `GET /download/:package/:version/:os/:arch` returns `403` before
  artifact lookup or storage access when the requested version carries a known critical CVE.

## Version 0.1.0: Initial Release

Initial Walrus release: a configuration-driven package ingress engine that discovers, caches, and
serves software package binaries from upstream sources.

- Added the Node.js 24 + TypeScript Express service with PostgreSQL metadata storage and local/GCS
  artifact storage backends.
- Added TOML-driven package definitions in `packages/`, including discovery, version grouping,
  retention, checksum, and platform matrix configuration.
- Implemented discovery strategies for GitHub Releases, JSON APIs, XML APIs, and directory
  listings, enabling packages to be added without service code changes.
- Added sync, download, retention, admin, and package metadata APIs, plus generated OpenAPI output
  and human-readable API docs.
- Added the artifact lifecycle pipeline from discovery through verified download, storage,
  availability tracking, retry handling, and removal.
- Added initial package configs for Go, Node.js, OpenJDK, Azul JDK, Maven, Gradle, Python, uv, and
  ripgrep.
- Added local development, validation, schema-checking, linting, formatting, migration, and Vitest
  test workflows documented under `docs/`.
