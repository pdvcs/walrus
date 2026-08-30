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

Every version group for a package, newest first. A platform filter narrows which artifacts count
as servable, not which groups are listed — a group with nothing servable still appears, carrying
`latest_available: null`.
Examples: [openjdk](/api/v1/packages/openjdk/groups), [golang](/api/v1/packages/golang/groups), [uv](/api/v1/packages/uv/groups)

`latest_available` is the latest cached version in the group that is free of known
critical CVEs (any CVSS base score — v3, v4, or v2 — >= 9.0, or a score-less CVE labeled CRITICAL). When every
cached version in a group carries a critical CVE — or is still inside its cooling-off
period — it is `null`, meaning nothing safe to recommend right now, **not** nothing cached.
Walrus never points this field at a version it knows to be critically vulnerable, nor at one
it would refuse to serve. Use
[`/api/v1/packages/:name/versions`](#get-apiv1packagesnameversions) to tell the two apart:
an embargoed version reports `cooling_off` with the timestamp it is released. Per-version CVE detail is available from
[`/api/v1/packages/:name/vulns`](#get-apiv1packagesnamevulns).

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
    { "group": "22", "is_lts": false, "latest_available": null },
    { "group": "21", "is_lts": true, "latest_available": "21.0.3" },
    { "group": "17", "is_lts": true, "latest_available": "17.0.11" }
  ]
}
```

**Status codes**

- `404` — package not found

---

### GET /api/v1/packages/:name/versions

All versions for a package, with platform availability and a version-level security status.
Examples: [openjdk](/api/v1/packages/openjdk/versions), [golang](/api/v1/packages/golang/versions), [uv](/api/v1/packages/uv/versions)

`status` is `blocked` when the version concretely matches a known critical CVE (any CVSS
base score — v3, v4, or v2 — >= 9.0, or a score-less CVE labeled CRITICAL) — this takes precedence over everything
else. It is `cooling_off` when no platform is servable yet because every candidate artifact is
inside its release embargo; `available_at` then carries the moment the first one is released.
Otherwise it is `available`. Range-uncomparable matches remain visible through the package
vulnerability endpoint but do not block the version.

Platform `status` is the artifact's lifecycle state — `pending`, `downloading`, `available`,
`failed`, `removed` — except that an embargoed artifact reports `cooling_off` with its own
`available_at`. Embargoed artifacts are stored as `pending`, so without this they would be
indistinguishable from ones the sync has simply not fetched yet.

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
      "status": "available",
      "available_at": null,
      "platforms": [
        { "os": "linux", "arch": "x86-64", "status": "available", "available_at": null },
        { "os": "mac", "arch": "aarch64", "status": "available", "available_at": null }
      ]
    },
    {
      "version": "21.0.4",
      "version_group": "21",
      "is_lts": true,
      "status": "cooling_off",
      "available_at": "2026-08-29T09:00:00.000Z",
      "platforms": [
        {
          "os": "linux",
          "arch": "x86-64",
          "status": "cooling_off",
          "available_at": "2026-08-29T09:00:00.000Z"
        }
      ]
    }
  ]
}
```

**Status codes**

- `404` — package not found

---

### GET /api/v1/packages/:name/versions/:group/latest

Latest available artifact for a version group and platform, excluding versions with a
concrete known-critical CVE match. If the newest version is blocked, Walrus returns the
next safe version; if every compatible cached version is blocked, it returns `404` and no
download URL. If nothing is servable only because the candidates are still inside their
cooling-off period, it returns `423` with `Retry-After` and `available_at` instead — a dated,
temporary withholding, distinct from the `202` that means "not synced yet, retry shortly".
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
    "download_url": "/download/openjdk/21.0.3/linux/x86-64",
    "requires_range": false
  }
}
```

`requires_range` is `true` when the artifact is too large to fetch in one request and an
unranged `GET` of it will be refused — see [range requests](#range-requests). Check it before
starting a download rather than discovering it from a `400`.

**Status codes**

- `202` + `Retry-After: 30` — no cached data; sync triggered, retry after 30 s
- `404` — package, group, or artifact not found
- `423` + `Retry-After` — nothing servable yet; every candidate is within its cooling-off
  period. Body includes `available_at`

---

### GET /download/:package/:version/:os/:arch

Download a binary. Streams directly from storage.

Downloads are refused when the requested version concretely matches a known critical CVE
(any CVSS base score — v3, v4, or v2 — >= 9.0, or a score-less CVE labeled CRITICAL).
CVEs known to be exploited in the wild (CISA KEV) are flagged but do not block on their own.

**Response headers** `200` and `206`

| Header              | Description                                                      |
| ------------------- | ---------------------------------------------------------------- |
| Content-Disposition | `attachment; filename="<filename>"`                              |
| Accept-Ranges       | `bytes`                                                          |
| ETag                | Validator for `If-Range`; changes when the artifact is re-synced |
| X-Content-Length    | Size of the **whole** artifact in bytes, on `206` as well        |
| X-Checksum-Sha256   | SHA-256 of the **whole** artifact (when available)               |
| X-Checksum-Sha1     | SHA-1 of the **whole** artifact (when available)                 |
| Content-Range       | `206` only: `bytes <start>-<end>/<total>`                        |

Neither a `200` nor a `206` carries `Content-Length`. Cloud Run buffers a response that declares
one and caps it at 32 MB, so declaring it would silently limit the chunk size a client may ask
for. On a `206`, `Content-Range` already states exactly how many bytes the response carries.

`X-Checksum-*` always describes the whole artifact, never the bytes of one chunk. **Verify after
reassembly, not per chunk.**

**Status codes**

- `200` — binary stream
- `206` — partial content, in response to a `Range` request
- `400` — artifact is over the ranged-transfer threshold and the request was not ranged (see below)
- `403` — version is blocked due to a known critical vulnerability
- `404` — artifact not found or not available; also when the package is disabled or removed (its TOML no longer exists)
- `416` + `Content-Range: bytes */<size>` — the requested range lies outside the artifact
- `423` + `Retry-After` — artifact is within the cooling-off period; body includes `available_at`

Every one of these gates applies identically to a ranged request. There is no path that serves
part of an artifact that a full `GET` would have refused.

#### Range requests

Standard `Range: bytes=…`, in the three single-range forms:

| Request               | Meaning                     |
| --------------------- | --------------------------- |
| `bytes=<start>-<end>` | Those bytes, both inclusive |
| `bytes=<start>-`      | From `start` to the end     |
| `bytes=-<n>`          | The last `n` bytes          |

A `<end>` past the end of the artifact is clamped rather than rejected. Only the requested bytes
are read from storage.

**Multi-range requests** (`bytes=0-1,8-9`) are **not** served as `multipart/byteranges`. Walrus
answers them with the full representation, which RFC 9110 permits. A range unit other than
`bytes` is ignored, likewise yielding the full representation.

`If-Range` is honoured against the `ETag`. If it does not match — because the artifact was
re-synced and the object at that key changed — walrus returns a full `200` instead of a `206`,
so a resumed download can never splice two different builds into one corrupt archive. An
`If-Range` in HTTP-date form is treated as a mismatch.

The server is indifferent to chunk size. Nothing in this contract fixes one.

#### Artifacts that require ranged transfer

A request has a hard 3600s deadline that cannot be raised. Past a certain size a single-request
download is not a slower path but one that cannot finish: a client sustaining 2 Mbps transfers
about 900 MB before the request is killed, leaving nothing to resume from. Above a configured
threshold (`RANGE_REQUIRED_BYTES`, 1 GB by default) walrus therefore **refuses** an unranged
`GET` rather than serving an hour of doomed transfer:

```http
GET /download/intellij/2026.2.1/windows/x86-64
```

```json
HTTP/1.1 400 Bad Request
Accept-Ranges: bytes

{
  "error": "Artifact is too large to transfer in one request; retry with a Range header. A single request cannot complete inside the 3600s server deadline at this size.",
  "code": "range_required",
  "file_size": 1729000000,
  "range_required_above_bytes": 1000000000,
  "suggested_chunk_bytes": 33554432
}
```

`400` is a deliberate choice: no status code means "you must use `Range`" — `416` is for a range
that cannot be satisfied and `428` is about lost updates — so the requirement is carried by the
`code` field, which will not change. `suggested_chunk_bytes` is a hint, not a constraint.

##### A stale `If-Range` above the threshold

Above the threshold the two rules above collide. An `If-Range` that no longer matches should be
answered by ignoring the range and sending the whole representation — but the whole
representation is exactly what walrus has just refused to send at this size. The mismatch is
therefore reported as a refusal too, under its own code:

```http
GET /download/intellij/2026.2.1/windows/x86-64
Range: bytes=1048576-34603007
If-Range: "sha256-an-older-build"
```

```json
HTTP/1.1 400 Bad Request
Accept-Ranges: bytes
ETag: "sha256-8aa16db629952300ab74d2d5e095150d1a534593e65bbbbd795b859759c00cbc"

{
  "error": "The artifact has changed since this download began, so the requested range belongs to a build walrus no longer holds. Discard any partial data and restart from byte 0 against the current ETag. This artifact is too large to be sent whole, which is why the mismatch is reported here rather than as a 200.",
  "code": "stale_range_validator",
  "file_size": 1614981679,
  "range_required_above_bytes": 1000000000,
  "suggested_chunk_bytes": 33554432
}
```

The distinction matters because the two codes ask for different things. `range_required` means
"send a `Range`"; `stale_range_validator` means "the bytes you already have are from a different
build — throw them away". A client that saw only the first would repeat the identical request
forever and never learn that its partial file is the problem. The current `ETag` rides on the
refusal, so restarting needs no extra round trip.

**Below** the threshold this case is unchanged and unremarkable: the range is ignored and the
whole representation is sent with `200`, exactly as RFC 9110 asks.

Below the threshold nothing changes: a plain `GET` behaves exactly as it always has, and ranged
transfer is a pure optimisation. Today every package walrus serves is below it.

Whether an artifact is above the threshold is published in its metadata as `requires_range` (see
`GET /api/v1/packages/:name/versions/:group/latest`), so a client can decide before it starts
downloading. The refusal is the backstop for clients that did not look.

The requirement keys on the request, never on the client: there is no `User-Agent` allowlist and
no privileged consumer.

---

## Admin API

Interactive UI available at [/admin/v1/](/admin/v1/)

All operator endpoints except `/admin/v1/login` require either the HttpOnly login cookie or an
`Authorization: Bearer <token>` minted by JSON login or `POST /admin/v1/tokens`. The authenticated
subject must also appear in the deployed `config/admins.toml` roster. Human-readable GETs redirect
to login; unauthenticated API calls return `401` and authenticated non-admins return `403`.

Endpoints under `/admin/v1/` provide:

- Package enable/disable
- Manual sync trigger (sync-all or per-package, with optional `?dry_run=true`)
- Artifact redownload and removal
- Version group retention management
- Sync job history
- CVE suppression preview/create/revoke and its audit trail

### GET /admin/v1/vuln-suppressions/audit

Returns suppression creation and revocation audit entries newest-first. This is the supported
production inspection path: Cloud Run has no shell or manual-SQL workflow. `limit` defaults to 50
and must be between 1 and 100; pass `next_before_id` back as `before_id` for the next page. Optional
`cve_id` filters the trail to one CVE.

```bash
curl "$WALRUS_URL/admin/v1/vuln-suppressions/audit?cve_id=CVE-2099-0001&limit=20"
```

---

## Vulnerability API

Walrus subsumes CVE-lookup for the packages it tracks (see
[engineering/docs/design.md](../../engineering/docs/design.md) and ADR-001). Data comes from
NVD (primary), CISA KEV (exploited-in-the-wild flag), and OSV (cross-check). Every response
carries a standing `disclaimer` and a `data_freshness` object (`nvd_last_sync` / `kev_last_sync`
/ `osv_last_sync` / `cvss_last_sync`, nullable until the first sync).

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
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-XXXXX"],
      "suppression": null
    }
  ],
  "counts": { "total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "kev": 0 },
  "data_freshness": {
    "nvd_last_sync": "…",
    "kev_last_sync": "…",
    "osv_last_sync": "…",
    "cvss_last_sync": "…"
  },
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

An active operator suppression is returned as
`{"reason":"…","expires_at":null}` instead of `null`.
Suppression excludes the CVE from the download gate but never hides it from this response.

### GET /api/v1/vulns/products/search?q=

Autocomplete over product names/aliases (trigram + prefix boost, top 10). Powers the admin explorer.

```bash
curl 'http://localhost:8080/api/v1/vulns/products/search?q=openj'
# { "query": "openj", "results": [ { "slug": "openjdk", "display_name": "…", "score": 100 } ] }
```

### GET /api/v1/vulns/products/:name

Returns vulnerability product metadata for one Walrus package: aliases (including provenance),
CPE vendor/product pairs, OSV mapping, tracking state, and a distinct CVE count. Unknown package
names return **404**; a known package without vulnerability metadata returns `tracked: false`.

```bash
curl 'http://localhost:8080/api/v1/vulns/products/openjdk'
```

> **NVD applicability limitation:** Walrus flattens NVD configuration trees to vulnerable
> application CPEs. It does not fully evaluate `AND`, `OR`, or `negate` environment predicates, so
> environment-dependent CVEs can be conservatively over-reported.

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
        {
          "cve_id": "…",
          "severity": "…",
          "fixed_in": "…",
          "is_kev": false,
          "matched_because": "…",
          "suppression": null
        }
      ]
    }
  ],
  "data_freshness": { "…": "…" },
  "disclaimer": "…"
}
```

Suppressed CVEs remain in each version's `vulns` array and carry the active assertion in
`suppression`; they do not make that version's download status blocked.

### GET /api/v1/packages/:name/availability

When a version became download-blocked, and which CVE caused it. Optional `?version=` limits
it to one version's history; without it you get the package's recent changes, newest first.

This is **history**, not a re-derivation of the current CVE rows — those only describe the
present. Ingestion runs unattended (see the ops runbook), so a scheduled job can turn a served
version into a `403` with no human watching; this endpoint is how you find out what happened
and when.

Rows are written only when a version's gate status actually **changes**. A version that stays
available forever produces none, and two-hourly ingestion does not append a row per run for a
version whose status has not moved. Both directions are recorded: a version blocked and later
unblocked — because its CVE was rescored below the gate, say — retains both transitions.

**Retention:** unbounded by design. Growth is driven by real status changes rather than by run
count, so the table stays small; rows are removed only when their package is deleted, via
`ON DELETE CASCADE`.

```json
{
  "package": "golang",
  "version": "1.26.4",
  "transitions": [
    {
      "version": "1.26.4",
      "status": "blocked",
      "cve_id": "CVE-2026-39821",
      "cvss_v3_score": null,
      "cvss_v4_score": 9.5,
      "cvss_v2_score": null,
      "severity": "CRITICAL",
      "severity_source": "nvd-cvss-v4",
      "source": "kev",
      "trigger": "internal",
      "at": "2026-08-26T18:49:47.733Z"
    }
  ]
}
```

`source` is the ingestion that caused the change (`nvd | kev | osv | cvss | all | backfill`) —
any source can block a version, not just CVSS enrichment. `trigger` is `internal` for a
scheduled run or `admin` for an operator. `cve_id` is null on an `available` transition:
nothing _causes_ a version to become servable except the absence of a blocking match.

The gate blocks on any CVSS base score >= 9.0 (v3, v4, or v2), so each transition carries
every score version the blocking CVE had at the time, plus `severity_source` saying which one
produced `severity` (`nvd-cvss-v3 | nvd-cvss-v4 | nvd-cvss-v2`) — a block recorded with a
sub-threshold v3 score and `severity_source: nvd-cvss-v4` was tripped by the v4 number.
Events written before this provenance was recorded (August 2026 and earlier) carry scores
only for v3, which may not state the full reason under today's policy.

**Status codes**

- `404` — package not found

---

### Ingestion triggers (internal / admin)

Vuln data is refreshed by external cron hitting `POST /internal/vuln-sync/:source`
(`nvd | kev | osv | cvss | all`), or the sync-now buttons in the admin explorer
(`POST /admin/v1/vuln-sync/:source`, audited in `admin_actions`). See the
[ops runbook](../../engineering/docs/build-release.md) for cadence and the one-time backfill.

**`cvss` — preview before applying.** The `cvss` source is a repair pass that fills in
severity for CVEs that have none (mostly OSV stubs NVD files as "Deferred"). Enrichment
can newly satisfy the >= 9.0 download gate, so a version that serves today can start
returning `403`. Both triggers accept a JSON body:

| Field     | Type    | Description                                           |
| --------- | ------- | ----------------------------------------------------- |
| `dry_run` | boolean | Report what would change, write nothing. `cvss` only  |
| `limit`   | integer | Bound the walk to N CVEs, in either mode. `cvss` only |

Both are rejected with `400` for any other source rather than being ignored — a caller
who asked for a preview must never get a live sync instead.

```bash
curl -XPOST .../internal/vuln-sync/cvss -H 'content-type: application/json' \
  -d '{"dry_run": true, "limit": 50}'
```

```json
{
  "source": "cvss",
  "dry_run": true,
  "preview": {
    "candidates": 3,
    "fetched": 3,
    "proposals": [
      {
        "cve_id": "CVE-2026-1111",
        "severity": "CRITICAL",
        "severity_source": "nvd-cvss-v3",
        "cvss_v3_score": 9.8,
        "cvss_v2_score": null,
        "crosses_critical_gate": true
      }
    ],
    "newly_blocked": [{ "package_name": "golang", "newly_blocked": ["1.26.4"] }]
  }
}
```

`newly_blocked` is the list to read before applying: those versions would begin returning
`403` from `/download`. A preview takes the same lock as the sync it models, so it returns
`409` if NVD ingestion is already running.

---

## Utility

### GET /health

```json
{
  "isAvailable": true,
  "gitUrl": "https://github.com/pdvcs/walrus",
  "ts": "2026-08-29T15:14:03.662Z",
  "started": "2026-08-29T15:10:00.000Z",
  "inGracePeriod": true,
  "version": "0.2.0"
}
```

The deployment availability check probes PostgreSQL. For 300 seconds after application startup it
returns HTTP 200 with `isAvailable: true` even if the database is not ready. After that grace
period, a database failure returns HTTP 503 with `isAvailable: false`. Successful and failed probe
results are cached for 60 seconds, and concurrent requests share one probe. The same check is also
available at `GET /app/health`.

### GET /app/status

Returns the health fields above plus detailed operational status:

```json
{
  "isAvailable": true,
  "gitUrl": "https://github.com/pdvcs/walrus",
  "ts": "2026-08-29T15:14:03.662Z",
  "started": "2026-08-29T15:10:00.000Z",
  "inGracePeriod": true,
  "version": "0.2.0",
  "vuln_data_freshness": {
    "nvd_last_sync": null,
    "kev_last_sync": null,
    "osv_last_sync": null,
    "cvss_last_sync": null
  },
  "vuln_sync_status": {
    "nvd": { "last_attempt": null, "last_success": null, "last_failure": null, "last_ok": null },
    "kev": { "last_attempt": null, "last_success": null, "last_failure": null, "last_ok": null },
    "osv": { "last_attempt": null, "last_success": null, "last_failure": null, "last_ok": null },
    "cvss": { "last_attempt": null, "last_success": null, "last_failure": null, "last_ok": null }
  },
  "degradations": []
}
```

`degradations` lists parts of unattended operation that currently need attention — stale or
failing vulnerability ingestion, stuck or disabled autonomous backfills — as
`{ "component", "reason" }` entries. Degradations do not change `isAvailable`; empty means
self-healing is healthy. The same list is shown as a banner on the admin UI.

### GET /

Public HTML landing page showing the running Walrus package version and links to operator login,
API documentation, deployment health, detailed application status, and the OpenAPI contract.

### GET /api

This page. Returns raw Markdown by default; send `Accept: text/html` for rendered HTML.

### GET /openapi.json

OpenAPI 3.1.0 specification for this API. [View](/openapi.json)

### Start an NVD backfill (operator API)

`POST /admin/v1/vuln-backfill` accepts JSON `{ "since": "YYYY-MM-DD", "package": "<name>" }` (both
optional) and returns `202 Accepted` with a durable job reference and status URL. Poll
`GET /admin/v1/vuln-backfill/:id` for lifecycle timestamps and CPE-pair progress. A currently
queued/running backfill returns `409` with `code: "already_running"`.

`package` restricts the walk to that package's CPE pairs — minutes instead of hours when you have
only added or changed one package. Two things to know about a targeted run:

- It does **not** advance the `nvd-cve` cursor. That cursor asserts "everything modified up to T
  has been ingested for every tracked package", which a one-package walk has not established;
  advancing it would make the next incremental sync skip that window for everything else.
- It is narrower in what it _fetches_, not in what it _records_. A CPE pair shared by several
  packages (`oracle:openjdk` is tracked by both `openjdk` and `azuljdk`) still writes affects rows
  for all of them, because the CVE genuinely affects all of them.

A package with no CPE pairs — one tracked only through an `[vulnerabilities].osv` mapping, like
`uv` — returns `400`; use the OSV sync for those. The same scope is available on the CLI as
`npm run vuln:backfill -- --package <name>`.
