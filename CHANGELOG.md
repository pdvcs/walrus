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

**Wave 11 — Git for Windows and the transform stage**

- **WAL-57 (Added):** A transform stage in the download pipeline, structured like discovery —
  a registry in `src/transform/` with one file per conversion, `tar-bz2-to-zip` first. The
  pipeline becomes `upstream → sourceHash → transform → outputHash → storage.upload`: the
  upstream digest is verified against the source bytes, the artifact's `checksum`/`file_size`
  describe the stored bytes, and output is deterministic (fixed deflate level, tar entry
  order, mtime from the tar header — byte-identical output across runs, verified against the
  real upstream archive). Peak memory is bounded by a measured link-cache window
  (`link_cache_bytes`), never artifact size; hardlinks are duplicated from that window and a
  target that falls out of it fails the artifact loudly. Symlinks and device/fifo entries fail
  the artifact unless explicitly listed in the config's `drop_symlinks` — nothing is skipped
  silently. A post-transform gate (`require_paths`, `min_entries`) blocks an empty or
  truncated output from reaching `available`, and the failure-path storage delete is now
  unconditional, since a transform can die mid-stream after a partial upload.
- **WAL-58 (Added):** Artifact provenance, via migration `0013_artifact_provenance.sql`:
  `source_checksum`, `source_file_size`, and `transform` join `artifacts`, while
  `checksum`/`file_size` keep meaning the bytes we serve. `upstream_url` is the source URL —
  no second column. The chain (source URL, source digest, transform identity) is exposed
  through `GET .../versions/:group/latest` and OpenAPI; for untransformed artifacts the new
  fields are NULL. Redownloading a transformed artifact now re-verifies against
  `source_checksum` instead of the stored zip digest it would never match.

**Wave 13 — CPE version semantics**

- **WAL-70 (Added):** Operator CVE suppressions are stored independently of ingestion and can be
  scoped to one package or all packages, optionally expiring. Public vulnerability responses keep
  suppressed CVEs visible with their reason; the critical gate ignores only active assertions.
  The API-first admin flow previews affected cached versions before create/revoke, audits both
  mutations with operator attribution, records availability transitions, and surfaces the active
  count in health degradations and the vulnerability explorer. The bounded
  `GET /admin/v1/vuln-suppressions/audit` endpoint exposes the create/revoke trail without
  production shell or database access.
- **WAL-59 (Added):** `npm run validate -- --transform` exercises a package's transforms for
  real against upstream — full pipeline into a no-op sink, nothing persisted — and reports
  entry count, output size, output digest, `require_paths` hits/misses, and symlink drops,
  per platform. Default off (minutes of CPU, hundreds of MB of transfer); configs without a
  transform behave exactly as before.
- **WAL-60 (Added):** `packages/walrus-gitwindows.toml` — Git for Windows served as `zip`
  transformed from upstream's streamable `Git-<version>-<arch>.tar.bz2`, because the portable
  `.7z.exe` is quarantined on managed laptops. Version pivots off the asset name
  (`asset_version_pattern`), since the tag (`v2.55.0.windows.5`) and the asset version
  (`2.55.0.5`) disagree; first-of-series three-component versions are spanned. Verified live:
  both arches transform (9,590 / 7,919 entries, `cmd/git.exe` and `usr/bin/bash.exe` present).
  CPE pairs remain deliberately unset until PO verification against the live NVD dictionary
  (WAL-60 MANUAL_TEST), and the served-size call is the PO's: measured **~162 MB (x86-64) /
  ~207 MB (arm64)** against 59 MB for the `.7z`.
- **WAL-61 (Changed):** Transform concurrency is bounded independently of
  `DOWNLOAD_CONCURRENCY` (`TRANSFORM_CONCURRENCY`, semaphore shared process-wide): the sync
  job runs transforms two at a time beside its eight IO-bound downloads, and the API service —
  which can run on-demand syncs and had inherited a 512 MiB memory default — is now pinned
  1Gi/1cpu with one transform at a time. Sized against the measured transform footprint
  (up to ~475 MiB of hardlink link cache per artifact on the arm64 tree).
- **WAL-62 (Added):** [ADR-006](engineering/decisions/ADR-006-transformed-artifacts.md) —
  _walrus may serve repackaged artifacts under stated conditions_. Accepted 2026-08-29. Records
  the eight conditions repackaging is permitted under, what a consumer verifies against
  (`checksum` = served bytes, `source_checksum` = what the vendor published), and what is
  given up: no vendor signature on the served zip, no byte-identity with upstream, and a
  162.4 MB zip against a 59 MB `.7z`.
- **WAL-57 (Fixed):** GitHub release discovery now carries the API's own `size` for each
  asset, so the truncation check prefers an independent number over the response's
  `Content-Length` (WAL-67's intent) instead of only when a checksum sidecar happens to exist.
- **WAL-73 (Fixed):** Review follow-ups on the transform stage. Two memory defects that made
  peak scale with artifact size rather than with `link_cache_bytes` — hardlink duplicates
  bypassing backpressure, and collected chunks retained for the life of the archive — plus the
  test assertion that could not have caught either (it sampled `heapUsed`, which cannot see
  Buffer memory, once at the end). The link cache now reserves space before an entry is
  collected instead of charging for it once stored, so `link_cache_bytes` is the ceiling the
  config, the changelog and the Cloud Run memory pins have been claiming rather than
  `budget + 2 x largest cached file`. An admin redownload of an artifact whose `transform` is
  recorded now fails with 409 when the live config resolves no transform for that platform,
  instead of quietly storing the raw `.tar.bz2` under the served `.zip` name and passing every
  check on the way. An upstream-published `size` no longer bypasses the content-coding bail
  that the response's own `Content-Length` obeys. `validate`'s spot-check line names the
  platform it actually checked rather than always `linux/x86-64`, which misreported every
  Windows-only package. Releasing a transform semaphore permit twice is now a no-op.

- **WAL-78 (Fixed):** CVE ranges are evaluated against the upstream version a served version
  embeds, where the package declares how ([ADR-008](engineering/decisions/ADR-008-cve-version-normalisation.md)).
  `gitwindows` serves `2.55.0.5` — Git 2.55.0, Windows rebuild 5 — against CVE ranges naming
  three-component Git, so `< 2.56.0` matched but a CVE naming `2.55.0` exactly, or bounding
  inclusively at it, silently did not: a build containing the affected Git looked clean. The rule
  is a regex in `[vulnerabilities].cve_version_extract`, reconciled to `packages` on boot like
  `osv_*`, and joined onto the affects rows so every evaluator has it without threading a
  parameter through nine call sites. The accepted cost is over-blocking — every `2.55.0.x` blocks
  under `<= 2.55.0` — which is deliberate, and `matched_because` now names both versions so a
  block is explicable. Packages declaring no rule are unaffected.

**Wave 12 — IntelliJ IDEA and multi-GB artifacts**

- **WAL-63 (Fixed):** The version sorter ranked a four-component build below the
  three-component version it extends — `2025.3.6` outranked its own `2025.3.6.1` — because a
  stable key was terminated with `~` (126) while overflow components were separated with
  `.` (46). `~` now both terminates a stable key and introduces every component past the third,
  so a longer version's key is a strict extension of the shorter one's and sorts above it.
  `version_sort` drives retention, so the effect was keeping a superseded build and pruning the
  newer one in any group that mixes component counts.
- **WAL-63 (Fixed):** `semver.parse(…, { loose: true })` does not merely reject a
  four-component version: with a multi-digit patch it reads the fourth component as an
  undelimited pre-release, turning `0.0.10.0` into `0.0.1-0.0` and keying it below `0.0.2`. The
  sorter now routes on the version's own shape before consulting semver instead of treating a
  failed parse as the signal. Keys for three-component versions — every version walrus currently
  stores — are byte-identical to before.
- **WAL-63 (Added):** `version_sort` is recomputed at boot for any row whose key no longer
  matches the sorter. The column is written once at discovery and there is no shell in
  production to run a fixup from, so a change to the algorithm would otherwise leave old rows
  keyed by the retired scheme indefinitely.

- **WAL-66 (Added):** Artifact downloads support `Range`. A single range — explicit,
  open-ended, or suffix — returns `206` with `Content-Range`, reading only those bytes from
  storage rather than the whole object; an unsatisfiable range returns `416`. `Accept-Ranges`
  and an `ETag` are advertised, and `If-Range` is honoured, so a client resuming against an
  artifact that has been re-synced gets a full `200` and starts over instead of splicing two
  builds into one corrupt archive. Multi-range requests are answered with the full
  representation, as RFC 9110 permits. `X-Checksum-*` still describes the whole artifact:
  verify after reassembly, not per chunk.
- **WAL-66 (Changed):** An unranged `GET` of an artifact above `RANGE_REQUIRED_BYTES` (1 GB by
  default) is now refused with `400` and `code: "range_required"` rather than served. Cloud
  Run's 3600s request deadline is not raisable, and at that size a single request cannot finish
  for any client under a few Mbps — "degrading gracefully" would mean an hour of doomed
  transfer and no partial result. Below the threshold nothing changes, which is every package
  walrus serves today. Artifact metadata carries `requires_range` so a client can tell before
  it starts.
- **WAL-67 (Changed):** GCS uploads set an explicit chunk size, which is what puts the client
  in resumable multi-chunk mode — previously a blip at 1.5 GB of a 1.6 GB upload discarded the
  whole transfer. The default is the value that is safe in an unpinned container (8 MiB); the
  sync job raises it to 32 MiB alongside the CPU and memory it now pins. Whole-transfer
  attempts drop from three to two: the storage half retries its own chunks now, so an outer
  restart only re-covers the upstream fetch.
- **WAL-67 (Fixed):** A truncated download is no longer marked `available`. The digest of the
  bytes that did arrive is perfectly self-consistent, so the checksum could not catch it; the
  received byte count is now compared against the size upstream advertises — the API's own
  number where it publishes one, otherwise `Content-Length` — and the object is deleted on a
  mismatch.
- **WAL-67 (Changed):** `sync_job_timeout` 3600s → 21600s. A first backfill of an
  IntelliJ-sized package moves 25.8 GB, which does not fit in an hour; the job maximum is 24h.

- **WAL-65 (Added):** A json-api sub-mode for APIs that key their downloads by platform rather
  than listing them — `files_shape = "platform-map"`. The existing nested-files mode assumes an
  array with the platform in a field, so a keyed object (JetBrains'
  `downloads: { windowsZip: …, macM1: … }`) silently yielded zero artifacts. Each
  `[[platforms]]` entry now selects its download by `os_upstream` matching the key; the URL,
  its checksum sidecar, and the published byte size come from the value. Filenames are taken
  from the URL rather than constructed, so an upstream that renames its artifact prefix
  mid-window is spanned without special-casing. The sub-mode is named rather than inferred from
  the response shape, and mixing its fields with the array shape's is a schema error rather
  than a silent no-op.
- **WAL-68 (Added):** `packages/walrus-intellij.toml` — IntelliJ IDEA Ultimate, served as the
  Windows `.win.zip` and the Apple Silicon `.dmg`, with everything (URL, sha256 sidecar,
  published size, release date) read from JetBrains' release API rather than constructed.
  Ultimate only: JetBrains has stopped publishing Community, and the API agrees. Groups come
  straight from the version — the first two components equal the API's own `majorVersion` for
  all 281 releases — and CVE tracking runs on `jetbrains:intellij_idea` (230 dictionary entries,
  verified live 2026-08-30), with no `cve_version_extract`, because IDEA's fourth component is
  JetBrains' own rather than a downstream rebuild counter. Ships at one group and one version so
  local and GCP Dev pull ~3.2 GB rather than the 25.8 GB production will hold; the production
  rule sits commented beside it. Both platforms stay configured even at that depth, since the
  `macM1` key and the sidecar are the only per-platform paths in the config and would otherwise
  reach production unexercised.
- **WAL-68 (Changed):** The platform-map sub-mode reports its skips once per sync instead of
  once per release and platform. JetBrains' feed carries every IDEA release back to 2011, and
  152 of its 281 records predate the `windowsZip` and `macM1` keys entirely — 276 warn lines on
  a feed where nothing was wrong. The summary is keyed by platform and carries a count and a
  sample, which is what distinguishes an asset that has gone missing from an archive that
  predates the keys.

**Wave 13 — CPE version semantics**

- **WAL-69 (Fixed):** A CPE whose version component is NA (`-`) no longer blocks every version.
  CPE 2.3 distinguishes NA from ANY (`*`), and ingestion collapsed the two — so an advisory that
  named no version was read as naming all of them. CNAs file that way against products they
  cannot version, which made an Arduino _extension_ flaw (CVE-2024-43488, NVD-rescored to 9.8
  CRITICAL) block every VS Code build walrus serves, along with four older NA advisories gating
  on CVSS v2 scores. Migration `0012_cve_affects_version_na.sql` records the distinction; the
  critical gate skips NA rows the way it already skips fail-open matches, while `*` with no
  bounds still means all versions. NA advisories stay visible on `/packages/:name/vulns` under
  `matched_because: "version-not-applicable"`.
- **WAL-69 (Fixed):** The vulnerability explorer no longer badges a non-gating CVE
  "blocks at 9.8". The gate exclusions (an NA-versioned CPE, a fail-open range match) were
  applied to `/download` but not to the explorer's own rendering, which computed the badge from
  the score alone — so the page went on naming CVE-2024-43488 a blocker after the fix had
  unblocked VS Code. The affected-range column now reads "not applicable (names no version)"
  rather than "all versions" for such rows, on the explorer, `/api/v1/vulns`, and the CVE
  detail endpoint.
- **WAL-71 (Added):** The vulnerability explorer offers a backfill scoped to the package being
  viewed, with an optional start date. The API has taken a `package` scope since WAL-37; only
  the affordance was missing (ADR-007).
- **WAL-71 (Fixed):** `createApp` now mounts `express.urlencoded`. The admin UI posts plain HTML
  forms, and with only `express.json()` every field was dropped silently — which made the new
  package-scoped backfill button run an unscoped 11-package backfill and return 303 as though it
  had worked.

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
