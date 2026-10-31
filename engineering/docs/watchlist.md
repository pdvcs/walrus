# Watch-only packages (`watchlist/`)

A **watched** package is tracked for vulnerabilities but never discovered,
downloaded, or served. Walrus holds no binaries for it and exposes no download
routes — it only answers "what CVEs affect this thing, and at which versions?".

This is the mechanism for tracking software that walrus has no intention of serving.

**Scope: applications, not libraries.** The watchlist is for standalone applications that
endpoint users install: editors, desktop tools, and the like. Current entries are
`notepad-plus-plus` and `sublime-text`. Libraries in a package ecosystem (PyPI, Maven, npm, ...)
are deliberately **not** tracked here: the userbase already covers them with Snyk and Sonatype,
so duplicating that coverage adds nothing. `requests` and `jackson-databind` were watch entries
and were removed for this reason (2026-10-31). The mechanism itself is not limited to
applications, so the `requests` examples below still illustrate the config shape.

## Why a separate directory

The vuln pipeline is keyed purely on `packages.name` and driven by
`package_cpes`, `package_aliases`, and `packages.osv_*`. Ingestion never reads
`versions` or `artifacts` at all; the cross-referencing query reads cached
versions only where they exist, and a watch package simply has none — which is
why `/api/v1/packages/requests/vulns` answers `tracked: true` with an empty
`versions` array. So vuln tracking has always been independent of
serving — the only thing standing in the way was that a `packages` row could
only originate from a `packages/*.toml`, which mandates `discovery`,
`versioning`, and a non-empty `platforms` array.

Rather than make those conditionally optional (which would weaken validation for
genuinely served packages — a typo'd `platforms` block would stop failing),
watch-only entries get their own directory and their own small schema:

|                                          | `packages/*.toml`                  | `watchlist/*.toml`               |
| ---------------------------------------- | ---------------------------------- | -------------------------------- |
| Schema                                   | `PackageConfigSchema`              | `WatchConfigSchema`              |
| Loader                                   | `src/services/package-registry.ts` | `src/services/watch-registry.ts` |
| `discovery` / `versioning` / `platforms` | required                           | **rejected** (unknown key)       |
| `[vulnerabilities]`                      | optional                           | **required**                     |
| Gets a `SyncService`                     | yes                                | no                               |
| `packages.enabled` on insert             | `true`                             | `false`                          |
| `packages.watch_only`                    | `false`                            | `true`                           |

`packages/` keeps meaning "things walrus serves".

Both schemas are strict: an unknown key is an error that names the key, not something
silently dropped. Dropping a full `packages/*.toml` into `watchlist/` therefore fails to load
(and fails `npm run check-schemas`) instead of quietly becoming a watch-only package.

A name must live in exactly one directory, because both share the `packages.name` key. If a
name appears in both, the served package wins: boot logs an error, the watch entry is ignored,
and `npm run check-schemas` fails.

## How it stays out of the serving path

Watch rows are seeded with `enabled = false`, which is what the serving surface
already filters on:

- `/api/v1/packages` lists `listPackages(pool, true)` → excluded.
- `/api/v1/packages/:name/groups` requires `pkg.enabled` → 404.
- The public catalog (`/packages`) and `/download` refuse disabled packages → 404.
- The admin dashboard iterates the configured `syncServices` map, which watch
  entries never join, and `PATCH /admin/v1/packages/:name` only accepts served names.
- `runSync` / `runSyncAll` refuse or skip disabled packages (moot — a watch
  package has no sync service to begin with).

The vuln routes never consult `enabled`, so they work normally:
`/api/v1/vulns?product=requests`, `/api/v1/packages/requests/vulns`, and the
resolver/autocomplete all resolve it like any other tracked package.

### Why `watch_only` as well as `enabled = false`

`enabled = false` alone cannot say _why_ a row is disabled: an operator disable, a
tombstone (WAL-53) and a watch entry all look the same. Reading it as "watch-only" was
actively wrong once tombstoning existed — the removal sweep, given only served names,
tombstoned every watch row on each boot, and the revive then set `enabled = true`,
publishing it into the serving routes.

So `packages.watch_only` (migration `0019`) records the kind explicitly. Reconcile owns it
and rewrites it from disk on every boot:

- The tombstone sweep takes the **union** of served and watched names as "configured".
  This is why `reconcileAllPackageVulns` takes both lists and every entrypoint (boot, the
  backfill script, the backfill job) goes through it — reconciling only one half would
  tombstone the other.
- Reviving a tombstone sets `enabled = NOT watch_only`, so a revived watch row stays disabled.
- Moving a file between directories flips the marker and `enabled` follows once:
  `packages/` → `watchlist/` disables the package; `watchlist/` → `packages/` enables it.
  After that, an operator's manual disable is respected on later boots as usual.
- Metrics report these rows as `walrus_packages{state="watch"}` rather than `disabled`.

Watch packages are listed (read-only) at `/watched` for anyone, and at `/admin/v1/watched` for
operators — each a top-level "Watched" item in its nav, next to Packages. Both show the latest
version, posture, CPE pairs, OSV mapping and backfill state; the operator page adds retry counts
and upstream error text, which the public one deliberately omits. Moving an entry to `packages/`
is the way to start serving it.

## Adding an entry

```toml
name = "requests" # lowercase, hyphens; becomes packages.name
display_name = "Requests"
vendor = "Python Software Foundation"
website = "https://pypi.org/project/requests/"
description = "..."

[latest] # optional: how to find the current release (see below)
type = "json"
url = "https://pypi.org/pypi/requests/json"
version_path = "$.info.version"

[vulnerabilities]
cpes = ["python:requests"] # NVD CPE 2.3 vendor:product, first = primary
osv = { ecosystem = "PyPI", name = "requests" }
aliases = ["requests", "python requests"]
```

The `[vulnerabilities]` block is the same schema used by served packages — see
`engineering/docs/package-config.md`.

### `[latest]` — knowing what the current release is

Walrus discovers no versions for a watch entry, so by itself it cannot say whether the
_current_ release is affected. `[latest]` is a deliberately small lookup — it resolves **one**
version string and stores it on the package row (`latest_version`); no `versions` or
`artifacts` rows are created. Two forms:

```toml
# Read one value out of a JSON document (PyPI, npm registry, crates.io, ...)
[latest]
type = "json"
url = "https://pypi.org/pypi/requests/json"
version_path = "$.info.version" # JSONPath
tag_pattern = "^v(.+)$" # optional; one capture group, applied to the value

# Or a GitHub repo's latest non-prerelease release
[latest]
type = "github-release"
repo = "hashicorp/terraform"
tag_pattern = "^v(.+)$" # optional; default strips a leading "v"
```

It is refreshed daily by the `walrus-watch-versions` scheduler job
(`POST /internal/watch-versions/refresh`) and once, best-effort, at boot. A failed lookup keeps
the previous good value and records `latest_version_error` (shown on `/admin/v1/watched`); a
total failure answers `502` so the scheduler retries and the existing job-failure alert fires.
Without `[latest]` the package is still fully tracked — posture just needs an explicit
`?version=`. Outbound hosts (`pypi.org`, `api.github.com`, ...) use the `discovery` egress
purpose, so an enterprise `WALRUS_EGRESS_RULES` setup must allow them.

## Reading a watched package's posture

```bash
curl localhost:8080/api/v1/watchlist                                  # all watched, latest version each
curl localhost:8080/api/v1/packages/requests/posture                  # its latest version
curl 'localhost:8080/api/v1/packages/requests/posture?version=2.30.0' # any specific version
```

The answer is `clean`, `vulnerable` or `unknown`, with severity counts, every advisory with its
`fixed_in`, and `upgrade_to` (the lowest version that clears them all). See the posture entry in
`src/routes/api-docs.md` for the full contract. The rule worth knowing here: **`clean` is only
returned once every configured source has been read** (`vuln_backfill_completed_at` for NVD,
`osv_synced_at` for OSV). A freshly added entry is `unknown` / `coverage-incomplete` until its
backfill finishes — never `clean` — so "we haven't looked" cannot be mistaken for "nothing there".

Verify identifiers against the live upstreams before committing; the vendor you
expect is often not the vendor NVD files under (Terraform is still `hashicorp`
post-IBM-acquisition, with no `ibm:*` CPE in existence):

```bash
# Which vendor:product pairs actually exist?
curl -s "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=terraform&resultsPerPage=200" \
  | jq -r '.products[].cpe.cpeName | split(":")[2:5] | join(":")' | sort | uniq -c | sort -rn

# How many CVEs does the pair carry?
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=cpe:2.3:a:hashicorp:terraform" \
  | jq '.totalResults'

# Does OSV know it?
curl -s -X POST https://api.osv.dev/v1/query -H 'content-type: application/json' \
  -d '{"package":{"ecosystem":"Go","name":"github.com/hashicorp/terraform"}}' | jq '.vulns | length'
```

Then:

```bash
npm run check-schemas   # validates packages/ and watchlist/ together
```

Entries are reconciled into the DB at boot (`reconcileAllWatchVulns`) and by the
standalone backfill entrypoints via `reconcileAllVulnConfigsFromDisk`, so
`npm run vuln:backfill` picks up new CPE pairs on a fresh database without the
app running.

## Caveats

- **CPE pairs are the unit of NVD backfill.** Each new pair adds a
  `virtualMatchString` pass over the NVD API. With an `NVD_API_KEY` this is
  cheap; keyless it is roughly 10x slower. After adding an entry you usually
  want a targeted backfill rather than a full one:

  ```bash
  npm run vuln:backfill -- --package requests
  # or: curl -X POST localhost:8080/internal/vuln-backfill \
  #       -H 'content-type: application/json' -d '{"package":"requests"}'
  ```

  A targeted run deliberately does not advance the `nvd-cve` cursor — see the
  operator API notes in `src/routes/api-docs.md`. It also reads OSV for that one package, so an
  OSV-primary entry is complete when its backfill finishes rather than after
  the next weekly `osv` run. (The daily `walrus-vuln-backfill-auto` sweep does this on its own
  for a new entry; the manual command is for when you do not want to wait.)

- **OSV-only entries are not auto-backfilled.** The backfill sweep and the targeted run are
  driven by CPE pairs; an entry with no `cpes` waits for the weekly `osv` sync and is `unknown`
  until then.

- **Pick the right product.** `hashicorp:terraform_enterprise` is the
  self-hosted server, and `hashicorp:terraform_provider` covers providers —
  neither is the Terraform CLI. Tracking the wrong pair produces confident
  false positives.
- **OSV aliasing duplicates rows.** A CVE carried by more than one OSV advisory
  — `GHSA-*` alongside `GO-*` for Go, or `PYSEC-*` for PyPI — yields one
  `cve_affects` row per advisory (their `raw_cpe` differs by advisory id, so the
  dedupe constraint does not collapse them). `requests`, while it was a watch
  entry, was the clearest case: 16 advisories covering 8 distinct CVEs.
  `crossReferenceVersions` keys on `cve_id`, so API results are unaffected. This
  predates the watchlist and applies equally to golang/nodejs/python/uv.
