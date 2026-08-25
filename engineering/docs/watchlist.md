# Watch-only packages (`watchlist/`)

A **watched** package is tracked for vulnerabilities but never discovered,
downloaded, or served. Walrus holds no binaries for it and exposes no download
routes — it only answers "what CVEs affect this thing, and at which versions?".

This is the mechanism for looking up arbitrary open-source packages that walrus
has no intention of serving. `watchlist/terraform.toml` and
`watchlist/requests.toml` — the `requests` library from PyPI — are the two
example entries for this feature.

## Why a separate directory

The vuln pipeline is keyed purely on `packages.name` and driven by
`package_cpes`, `package_aliases`, and `packages.osv_*`. Ingestion never reads
`versions` or `artifacts` at all; the cross-referencing query reads cached
versions only where they exist, and a watch package simply has none — which is
why `/api/v1/packages/terraform/vulns` answers `tracked: true` with an empty
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
| `discovery` / `versioning` / `platforms` | required                           | ignored (silently stripped)      |
| `[vulnerabilities]`                      | optional                           | **required**                     |
| Gets a `SyncService`                     | yes                                | no                               |
| `packages.enabled` on insert             | `true`                             | `false`                          |

`packages/` keeps meaning "things walrus serves".

> **Caveat:** `WatchConfigSchema` is a plain `z.object()`, so Zod *strips* keys it
> does not know rather than rejecting them. Dropping a full `packages/*.toml` into
> `watchlist/` therefore loads without error and quietly discards everything that
> made it servable, leaving a watch-only package. See WAL-35 for making this an
> error instead.

## How it stays out of the serving path

Watch rows are seeded with `enabled = false`, which is what the serving surface
already filters on — no new column or migration was needed:

- `/api/v1/packages` lists `listPackages(pool, true)` → excluded.
- `/api/v1/packages/:name/groups` requires `pkg.enabled` → 404.
- The admin dashboard iterates the configured `syncServices` map, which watch
  entries never join.
- `runSync` / `runSyncAll` refuse or skip disabled packages (moot — a watch
  package has no sync service to begin with).

The vuln routes never consult `enabled`, so they work normally:
`/api/v1/vulns?product=terraform`, `/api/v1/packages/terraform/vulns`, and the
resolver/autocomplete all resolve it like any other tracked package.

`enabled` is deliberately overloaded here rather than given a sibling
`tracking_mode` column. It is honest — walrus does not serve these — and it
costs no migration. If watch entries ever need to be distinguished from a
package an operator merely disabled, that is the point to add the column.

## Adding an entry

```toml
name = "terraform"                 # lowercase, hyphens; becomes packages.name
display_name = "Terraform"
vendor = "HashiCorp (IBM)"
website = "https://developer.hashicorp.com/terraform"
description = "..."

[vulnerabilities]
cpes = ["hashicorp:terraform"]     # NVD CPE 2.3 vendor:product, first = primary
osv  = { ecosystem = "Go", name = "github.com/hashicorp/terraform" }
aliases = ["terraform", "tf"]
```

The `[vulnerabilities]` block is the same schema used by served packages — see
`engineering/docs/package-config.md`.

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
  npm run vuln:backfill -- --package terraform
  # or: curl -X POST localhost:8080/internal/vuln-backfill \
  #       -H 'content-type: application/json' -d '{"package":"terraform"}'
  ```

  A targeted run deliberately does not advance the `nvd-cve` cursor — see the
  operator API notes in `src/routes/api-docs.md`.

- **Pick the right product.** `hashicorp:terraform_enterprise` is the
  self-hosted server, and `hashicorp:terraform_provider` covers providers —
  neither is the Terraform CLI. Tracking the wrong pair produces confident
  false positives.
- **OSV aliasing duplicates rows.** A CVE carried by more than one OSV advisory
  — `GHSA-*` alongside `GO-*` for Go, or `PYSEC-*` for PyPI — yields one
  `cve_affects` row per advisory (their `raw_cpe` differs by advisory id, so the
  dedupe constraint does not collapse them). `requests` is the clearest case:
  16 advisories covering 8 distinct CVEs. `crossReferenceVersions` keys on
  `cve_id`, so API results are unaffected. This predates the watchlist and
  applies equally to golang/nodejs/python/uv and to both watchlist entries.
