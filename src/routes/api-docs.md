# Walrus API

Walrus is a policy- and identity-aware ingress engine for software packages.
It discovers, caches, and serves package binaries based on policy expressed in configuration files.

The goal is to provide a useful foundation for package manager servers and clients and provide them APIs to get package metadata and the binaries themselves.

See also: [OpenAPI spec](/openapi.json)

---

## Public API

Useful for package-manager servers (to read metadata) and package-manager clients (to download binaries).

### GET /api/v1/packages/

List all enabled packages. [Try it](/api/v1/packages/)

**Response** `200`

```json
{
  "packages": [
    {
      "name": "uv",
      "display_name": "uv",
      "vendor": "Astral",
      "description": "Python package manager",
      "website": "https://github.com/astral-sh/uv"
    }
  ]
}
```

---

### GET /api/v1/packages/:name/groups

Version groups for a package, optionally filtered to groups that have artifacts for a given platform.
Examples: [openjdk](/api/v1/packages/openjdk/groups), [golang](/api/v1/packages/golang/groups), [uv](/api/v1/packages/uv/groups)

**Query parameters**

| Name | Type   | Description                            |
| ---- | ------ | -------------------------------------- |
| os   | string | Filter by OS (e.g. `linux`)            |
| arch | string | Filter by architecture (e.g. `x86-64`) |

**Response** `200`

```json
{
  "package": "openjdk",
  "groups": [
    { "group": "21", "is_lts": true, "latest_available": "21.0.3" },
    { "group": "17", "is_lts": true, "latest_available": "17.0.11" }
  ]
}
```

**Status codes**

- `404` — package not found

---

### GET /api/v1/packages/:name/versions

All versions for a package, with platform availability.
Examples: [openjdk](/api/v1/packages/openjdk/versions), [golang](/api/v1/packages/golang/versions), [uv](/api/v1/packages/uv/versions)

**Query parameters**

| Name | Type    | Description                         |
| ---- | ------- | ----------------------------------- |
| lts  | boolean | If `true`, return only LTS versions |

**Response** `200`

```json
{
  "package": "openjdk",
  "version_groups": ["21", "17"],
  "versions": [
    {
      "version": "21.0.3",
      "version_group": "21",
      "is_lts": true,
      "platforms": [
        { "os": "linux", "arch": "x86-64", "status": "available" },
        { "os": "mac", "arch": "aarch64", "status": "available" }
      ]
    }
  ]
}
```

**Status codes**

- `404` — package not found

---

### GET /api/v1/packages/:name/versions/:group/latest

Latest available artifact for a version group and platform.
Example: [openjdk group 21, linux/x86-64](/api/v1/packages/openjdk/versions/21/latest?os=linux&arch=x86-64)

**Query parameters**

| Name | Type   | Description         |
| ---- | ------ | ------------------- |
| os   | string | Target OS           |
| arch | string | Target architecture |

**Response** `200`

```json
{
  "package": "openjdk",
  "version_group": "21",
  "version": "21.0.3",
  "is_lts": true,
  "artifact": {
    "os": "linux",
    "arch": "x86-64",
    "filename": "OpenJDK21U-jdk_x64_linux_hotspot_21.0.3_9.tar.gz",
    "file_size": 207109699,
    "checksum": "abc123...",
    "checksum_type": "sha256",
    "download_url": "/download/openjdk/21.0.3/linux/x86-64"
  }
}
```

**Status codes**

- `202` + `Retry-After: 30` — no cached data; sync triggered, retry after 30 s
- `404` — package, group, or artifact not found

---

### GET /download/:package/:version/:os/:arch

Download a binary. Streams directly from storage.

**Response headers** `200`

| Header              | Description                         |
| ------------------- | ----------------------------------- |
| Content-Disposition | `attachment; filename="<filename>"` |
| X-Content-Length    | File size in bytes                  |
| X-Checksum-Sha256   | SHA-256 checksum (when available)   |
| X-Checksum-Sha1     | SHA-1 checksum (when available)     |

**Status codes**

- `200` — binary stream
- `404` — artifact not found or not available
- `423` + `Retry-After` — artifact is within the cooling-off period; body includes `available_at`

---

## Admin API

Interactive UI available at [/admin/v1/](/admin/v1/)

Endpoints under `/admin/v1/` provide:

- Package enable/disable
- Manual sync trigger (sync-all or per-package, with optional `?dry_run=true`)
- Artifact redownload and removal
- Version group retention management
- Sync job history

---

## Vulnerability API

Walrus subsumes CVE-lookup for the packages it tracks (see
[engineering/docs/design.md](../../engineering/docs/design.md) and ADR-001). Data comes from
NVD (primary), CISA KEV (exploited-in-the-wild flag), and OSV (cross-check). Every response
carries a standing `disclaimer` and a `data_freshness` object (`nvd_last_sync` / `kev_last_sync`
/ `osv_last_sync`, nullable until the first sync).

> **Disclaimer:** Absence of results does not imply a product/version is safe — the underlying
> public sources may lag or be incomplete.

### GET /api/v1/vulns?product=&version=&include_unmatched=

The flagship lookup. Resolves a product name/alias (fuzzy), then returns known CVEs, optionally
range-checked against `version`.

```bash
curl 'http://localhost:8080/api/v1/vulns?product=openjdk&version=11.0.2'
```

```json
{
  "query": { "product": "openjdk", "version": "11.0.2" },
  "match": {
    "resolved": true,
    "product_slug": "openjdk",
    "display_name": "Eclipse Temurin OpenJDK",
    "confidence": 1.0,
    "method": "slug-exact",
    "candidates": []
  },
  "vulns": [
    {
      "cve_id": "CVE-2023-XXXXX",
      "severity": "HIGH",
      "cvss_v3_score": 7.5,
      "summary": "…",
      "affected": { "range": "< 20", "matched_because": "11.0.2 < 20" },
      "fixed_in": "20",
      "is_kev": false,
      "sources": ["nvd"],
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-XXXXX"]
    }
  ],
  "counts": { "total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0 },
  "data_freshness": { "nvd_last_sync": "…", "kev_last_sync": "…", "osv_last_sync": "…" },
  "disclaimer": "Absence of results does not imply…"
}
```

The three **"no result"** cases are deliberately distinguishable:

- **Resolved + `vulns: []`** — the product is tracked and has zero known CVEs (at the given version).
- **`resolved: false` (HTTP 200)** — the name didn't resolve; `match.candidates[]` holds suggestions.
  Not an error — clients render an autocomplete/"did you mean".
  ```bash
  curl 'http://localhost:8080/api/v1/vulns?product=asdfgh'   # → 200, resolved:false, candidates[]
  ```
- **`version_parse_warning` present** — the version string was uncomparable; matching CVEs are
  **included** flagged `matched_because: "range-uncomparable"` (fail-open, never silently dropped).
  ```bash
  curl 'http://localhost:8080/api/v1/vulns?product=openjdk&version=lol'
  ```

Missing `product` → **HTTP 400**.

### GET /api/v1/vulns/products/search?q=

Autocomplete over product names/aliases (trigram + prefix boost, top 10). Powers the admin explorer.

```bash
curl 'http://localhost:8080/api/v1/vulns/products/search?q=openj'
# { "query": "openj", "results": [ { "slug": "openjdk", "display_name": "…", "score": 100 } ] }
```

### GET /api/v1/cves/:cveId

CVE detail: metadata, KEV status, affected products (described ranges + provenance), references.
Malformed id → **400**; unknown id → **404**.

```bash
curl 'http://localhost:8080/api/v1/cves/CVE-2023-40031'
```

### GET /api/v1/packages/:name/vulns

**Walrus-native.** Cross-references CVEs against the package's **cached versions**. Optional
`?version=` restricts to one. Packages with no `[vulnerabilities]` config return `tracked: false`
(HTTP 200, not an error); unknown packages → **404**.

```bash
curl 'http://localhost:8080/api/v1/packages/openjdk/vulns'
```

```json
{
  "package": "openjdk",
  "tracked": true,
  "versions": [
    {
      "version": "11.0.2",
      "version_group": "11",
      "counts": { "total": 12, "critical": 1, "high": 6, "medium": 5, "low": 0, "kev": 0 },
      "vulns": [
        { "cve_id": "…", "severity": "…", "fixed_in": "…", "is_kev": false, "matched_because": "…" }
      ]
    }
  ],
  "data_freshness": { "…": "…" },
  "disclaimer": "…"
}
```

### Ingestion triggers (internal / admin)

Vuln data is refreshed by external cron hitting `POST /internal/vuln-sync/:source`
(`nvd | kev | osv | all`), or the sync-now buttons in the admin explorer
(`POST /admin/v1/vuln-sync/:source`, audited in `admin_actions`). See the
[ops runbook](../../engineering/docs/build-release.md) for cadence and the one-time backfill.

---

## Utility

### GET /health

```json
{
  "status": "ok",
  "service": "walrus",
  "vuln_data_freshness": { "nvd_last_sync": null, "kev_last_sync": null, "osv_last_sync": null }
}
```

### GET /api

This page. Returns raw Markdown by default; send `Accept: text/html` for rendered HTML.

### GET /openapi.json

OpenAPI 3.1.0 specification for this API. [View](/openapi.json)
