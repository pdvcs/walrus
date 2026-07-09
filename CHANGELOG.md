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
