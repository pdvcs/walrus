# Walrus - Design & Architecture

Walrus is a policy- and identity-aware ingress engine for software packages.
It discovers, caches, and serves package binaries based on policy expressed in configuration files.

The goal is to provide a useful foundation for package manager servers and clients and provide them APIs to get package metadata and the binaries themselves.

---

## System Architecture

```
                          INTERNET
                             |
      api.adoptium.net   nodejs.org   github.com   go.dev  ...
                             |
                    [Cloud NAT Gateway]
                             |
 +===========================+=================================+
 |                      GCP PROJECT                            |
 |                                                             |
 |  +----------------------+    +---------------------------+  |
 |  |   Walrus API         |    |   Discovery Workers       |  |
 |  |   (Cloud Run)        |    |   (Cloud Run Jobs)        |  |
 |  |                      |    |                           |  |
 |  |  - Package metadata  |    |  - Scheduled polling      |  |
 |  |  - Version listing   |    |  - Binary download        |  |
 |  |  - Binary download   |    |  - Checksum verify        |  |
 |  |  - Admin endpoints   |    |                           |  |
 |  +--------+---+---------+    +------+--------------------+  |
 |           |   |                     |                       |
 |      +----+---+---------------------+---+                   |
 |      |   Cloud SQL (Postgres)           |                   |
 |      |   packages / versions /          |                   |
 |      |   artifacts / sync_jobs          |                   |
 |      +----------------------------------+                   |
 |                     |                                       |
 |      +--------------+------------------------------+        |
 |      |   GCS Bucket (walrus-artifacts)             |        |
 |      |   {pkg}/{ver}/{os}/{arch}/{filename}        |        |
 |      +---------------------------------------------+        |
 +=============================================================+
                |                              |
            [Network]                      [Network]
                |                              |
      +------------------+           +------------------+
      | pkg mgr metadata |           |  pkg mgr client  |
      |      server      |           |                  |
      |                  |           |                  |
      |  Reads metadata, |           |  Downloads       |
      |  builds recipes  |           |  binaries from   |
      +------------------+           |  Walrus directly |
                                     +------------------+
```

### Components

| Component                | Runtime               | Purpose                                         |
| ------------------------ | --------------------- | ----------------------------------------------- |
| **Walrus API**           | Cloud Run (always-on) | Metadata API + binary downloads + admin         |
| **Discovery Workers**    | Cloud Run Jobs        | Scheduled and on-demand sync                    |
| **Cloud SQL (Postgres)** | Managed Postgres      | Package/version/artifact metadata, job tracking |
| **GCS Bucket**           | Standard storage      | Cached binary artifacts                         |

---

## Package Definitions (TOML)

The central design goal is that **adding a package requires only a config file, not code**.

Each package is a TOML file in `packages/`. The format captures everything needed to discover versions and download binaries:

- **`[discovery]`** — which strategy to use and its parameters
- **`[versioning]`** — how to parse and group version strings
- **`[retention]`** — how many versions to keep per release series
- **`[checksum]`** — how to obtain the SHA256 (or SHA1) for each artifact
- **`[[platforms]]`** — one block per supported OS/arch combination

TOML was chosen over YAML for its support for inline comments and its insensitivity to indentation, making the files easier to read and maintain by human operators.

See `packages/walrus-uv.toml`, `packages/walrus-openjdk.toml`, and `packages/walrus-golang.toml` for representative examples of the three main discovery patterns.

---

## Discovery Engine

Version discovery is implemented as a strategy pattern (`src/discovery/`). Each strategy knows how to talk to a particular type of upstream source and emit a uniform list of discovered versions with their artifact URLs and checksums.

### Strategies (in preference order)

**`github-releases`** — Calls the GitHub Releases API. Filters by tag pattern, extracts assets by matching the `filename_template` against release asset names. Cleanest option when a package publishes to GitHub Releases.

**`json-api`** — Generic JSON API with JSONPath navigation. Supports two submodes:

- _Two-step_: first fetches a version list, then makes a per-version API call to get artifact details. Used by Adoptium (OpenJDK), which has a dedicated `/assets/feature_releases/{version}` endpoint.
- _Inline_: a single API call returns both versions and their artifact files in one response. Used by Go's `go.dev/dl/?mode=json` API. Activated by omitting `release_url_template` in the config.

**`xml-api`** — For sources that expose version information as XML (e.g., Maven Central's directory listing as Atom/RSS). Less common but needed for Maven and Gradle.

**`directory-listing`** — Fetches a directory listing page and matches filenames by pattern. Used when no structured API exists but files are served from a browsable directory.

**`html-scrape`** — Regex extraction from HTML. Last resort only; HTML structure changes without notice and makes configs brittle. Not implemented in the initial phases.

### Why a Strategy Pattern?

Each upstream has a completely different API shape. The strategy pattern keeps this complexity contained: the rest of the system (sync orchestration, retention, DB writes) only ever sees the common `DiscoveredVersion[]` output. Adding a new discovery mechanism means adding one new file in `src/discovery/` and a new `type` value in the TOML schema, with no changes elsewhere.

---

## Database Schema

Five tables in Postgres:

```
packages          — one row per managed package (mirrors TOML config)
  └── versions    — one row per discovered version
        └── artifacts — one row per version × platform combination
sync_jobs         — audit trail for each discovery run
admin_actions     — log of admin operations (force-sync, redownload, remove)
```

The `artifacts` table is the heart of the system. Each row tracks a single binary file through its lifecycle:

```
pending → downloading → available
                     └→ failed
available → removed (via admin)
```

Only `available` artifacts are served to clients. The API checks status before responding to download requests.

`version_sort` (a zero-padded string) is stored alongside the raw version string to enable correct lexicographic ordering without parsing in SQL.

We uses plain `pg` (node-postgres) with hand-written SQL queries.

Why no ORM? The query surface is small and well-defined (five tables, stable schema), and the queries themselves
benefit from explicit SQL -- especially version_sort ordering, the ON CONFLICT DO NOTHING upserts, and
status-filtered artifact queries. An ORM would add abstraction without much benefit here.

---

## Download Pipeline

When a sync discovers a new version:

1. Insert `versions` and `artifacts` rows (status `pending`)
2. Acquire a download slot (semaphore: max 4 total, max 2 per package)
3. Stream the binary from the upstream URL directly to GCS — no local temp file
4. Calculate checksum during the stream
5. Compare against the expected checksum (from API, sidecar file, or GitHub asset)
6. On success: set status `available`, record `gcs_path`, `file_size`, `checksum`
7. On failure: set status `failed`, record error; retry up to 3× (1 min, 5 min, 15 min)
8. After all downloads: enforce retention (delete oldest artifacts beyond the `versions_per_group` limit)

Streaming without a temp file is important: artifacts can be hundreds of megabytes, and holding them in memory or on disk before uploading would require proportionally large worker instances.

---

## API Design

### Metadata API (`/api/v1/`) — consumed by package manager servers

- `GET /api/v1/packages` — list all enabled packages
- `GET /api/v1/packages/:name/versions` — list versions with platform availability; `?lts=true` filters to LTS only
- `GET /api/v1/packages/:name/versions/:versionGroup/latest` — get the latest version in a release series for a given platform; returns the download URL, checksum, and file size

The last endpoint is the primary one a package manager server might use. A single request
would give it everything it needed to build a recipe.

### Binary Download API (`/download/`) — consumed by package manager clients

- `GET /download/:package/:version/:os/:arch` — streams the binary from GCS with appropriate headers including `X-Checksum-Sha256`

Clients download directly from Walrus rather than from the package manager server, avoiding extra
hops. In the future, this will allow us to add identity-awareness (authn and authz) to the API.

---

### Admin API (`/admin/v1/`) — operator tooling

- Force sync (with optional `?dry_run=true`)
- Redownload a specific artifact
- Remove a version's artifacts
- Enable/disable a package
- View sync job history

### Internal API (`/internal/sync`) — called by Cloud Scheduler

Triggers the sync worker on a 6-hour schedule. Not exposed to the public network.

---

## Vulnerability Intelligence

Walrus subsumes the CVE-lookup capability of the standalone `vulncheck` service (ADR-001):
"does {product} version {X} have known CVEs?", plus a walrus-native cross-reference against the
versions walrus actually caches. It is a native port keyed to walrus packages — there is no
separate products table.

**Data model** (migration `0002_vulnerabilities.sql`): `cves` (denormalized NVD record + raw
JSONB, KEV flag), `cve_affects` (version ranges per package, `source` = `nvd` | `osv`, deduped
by a `UNIQUE NULLS NOT DISTINCT` constraint), `package_cpes` and `package_aliases`
(reconciled from each package's optional `[vulnerabilities]` TOML section at boot),
`vuln_sync_state` (per-source ingestion cursors), and `unresolved_queries` (alias-curation feed).
`packages` gains `osv_ecosystem` / `osv_name`.

**Matching core** (`src/vuln/`, ported behaviour-for-behaviour, property-tested):

- `normalize.ts` — name normalizer + variant generation (`++` → `plus`, squashed forms).
- `version-ranges.ts` — `compareVersions` (semver-first, segment-comparator fallback for
  `2021.1`, `1.0b`, `8.3.2.0`), `evaluateRange`, `describeRange`. **Never throws; uncomparable
  ⇒ fail open** flagged `range-uncomparable`. Deliberately separate from
  `common/version-utils.ts` (sort keys ≠ range evaluation).
- `cpe.ts` — CPE 2.3 formatted-string parser (splits on unescaped colons).
- `resolver.ts` — exact name → exact alias → pg_trgm + fuzzball rerank → unresolved with
  candidates (the messy-name/autocomplete IP).

**Ingestion** (`src/vuln/sync/`, no resident worker): NVD API 2.0 client (pagination, rate-limit
awareness, backoff), NVD sync (parse `cpeMatch[]`, join `package_cpes`, rebuild `nvd` affects
per CVE), KEV flagging, and OSV cross-check (provenance-tagged `osv` affects + stub CVEs).
Triggered by external cron on `/internal/vuln-sync/:source` (`nvd|kev|osv|all`), an admin
button, and a one-time `npm run vuln:backfill`. See the ops runbook in
[build-release.md](build-release.md).

**Query API** (`/api/v1/vulns`, `/api/v1/vulns/products/search`, `/api/v1/cves/:id`,
`/api/v1/packages/:name/vulns`) — Zod schemas in `src/routes/schemas.ts`, registered in
`openapi.ts`, `Schema.parse()` before send. The `/packages/:name/vulns` endpoint is the
headline walrus-native feature (join CVEs against cached `versions`); it powers the per-version
CVE badges in the admin UI. Every response carries a standing disclaimer and `data_freshness`.
`/health` gains a nullable `vuln_data_freshness`. Golden tests ported from vulncheck prove
behavioural parity.

**Out of scope (v1):** authn/authz + rate limiting, tracking tools walrus doesn't serve,
download-blocking of affected artifacts (v1 informs only).

---

## On-Demand Discovery

If an API client, typically a package manager server, requests a version that isn't in the database,
Walrus checks whether a sync ran in the last 30 minutes. If not, it triggers a targeted sync for that
package and returns `202 Retry-After: 30`. The package manager server should retry after the delay.

This handles the case where a version was just released and hasn't been picked up by the scheduled sync yet, without requiring real-time upstream calls on every metadata request.

---

## Version Grouping and Retention

The `version_group_extract` regex in each package's TOML defines how versions are bucketed into release series. This is not always the semver major — it's whatever the project uses as its maintenance series:

- Java: `"^(\\d+)"` → `"21"` (Java 21.x.x is a single series)
- Go: `"^(\\d+\\.\\d+)"` → `"1.24"` (Go major.minor is the series; Go 2.x doesn't exist)
- Node.js: `"^(\\d+)"` → `"22"` (same as Java)

`versions_per_group` then controls how many versions within each series to keep. When a new version is downloaded and the limit is exceeded, the oldest is removed from GCS and marked `removed` in the database (retained for audit).

---

## LTS Support

Some packages (Java, Node.js) have an LTS concept. Walrus supports three ways to determine which version groups are LTS:

- **`lts_source = "api"`** — read from the discovery API response. In two-step mode (Adoptium), `lts_api_path` extracts the list of LTS groups from the version-list response. In inline mode (Node.js), `release_lts_field` names a per-release field whose truthy string value (e.g. `"Jod"`) marks a release as LTS.
- **`lts_source = "even_major"`** — LTS = even-numbered major versions at or above a threshold (older Node.js convention)
- **`lts_source = "explicit"`** — a static list in the TOML config
- **`lts_support = false`** — no LTS concept (Go, uv, ripgrep)

---

## Storage Abstraction

The storage layer is behind a `StorageBackend` interface (`src/storage/types.ts`):

```typescript
interface StorageBackend {
  upload: (key: string, content: Buffer) => Promise<void>;
  download: (key: string) => Promise<Buffer>;
  delete: (key: string) => Promise<void>;
  exists: (key: string) => Promise<boolean>;
}
```

`STORAGE_BACKEND=gcs` (production) stores artifacts in the GCS bucket. `STORAGE_BACKEND=local` stores files under `LOCAL_STORAGE_PATH` using the same path convention. This means the full sync and download pipeline can be exercised locally without any GCP credentials.

---

## Local Development

The dev setup is intentionally minimal:

- Local Postgres (no Docker required)
- Local filesystem storage (`STORAGE_BACKEND=local`)
- All other logic — discovery, sync, API routes — runs identically to production

```bash
createdb walrus && createuser walrus
npm install
npm run migrate
npm run dev         # starts on localhost:8080
```

The `npm run validate` command exercises the discovery pipeline against real upstream APIs for a given package TOML, without writing to the database or storage. This is the primary tool for authoring and debugging package configs.

---

## Dry Run Mode

Two entry points for dry runs:

1. **`?dry_run=true`** on admin sync endpoints — useful for checking what a sync would do on a live instance without side effects
2. **`npm run validate`** — the CLI validator, used during package authoring

Both use the same code path: the sync service runs normally but with a no-op `StorageBackend` and no-op DB client injected, so real discovery and URL resolution happens but nothing is written.

---

## Project Structure

```
src/
  main.ts              # Express app entry point, route registration
  config/              # Environment variable loading and validation
  routes/              # Express route handlers (packages, download, admin, internal)
  services/            # Business logic (sync, version queries, download, retention, admin)
  discovery/           # Strategy implementations (github-releases, json-api, xml-api, directory-listing)
  db/
    client.ts          # Postgres connection pool + migration runner
    migrations/        # SQL migration files (0001_initial.sql, ...)
    queries/           # Typed query functions (packages, versions, artifacts, sync-jobs)
  storage/             # StorageBackend interface + GCS and local implementations
  common/              # Shared utilities (logging, version sorting, Result type)
  types/               # Zod schemas and inferred TypeScript types

packages/              # TOML package definition files (one per managed tool)
scripts/               # CLI tools (validate-package.ts)
tests/
  discovery/           # Strategy unit tests (mocked fetch, no network)
  services/            # Service unit tests
  db/                  # Integration tests (require running Postgres)
  routes/              # Route integration tests
```
