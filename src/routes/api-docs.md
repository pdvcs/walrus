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

## Utility

### GET /health

```json
{ "status": "ok", "service": "walrus" }
```

### GET /api

This page. Returns raw Markdown by default; send `Accept: text/html` for rendered HTML.

### GET /openapi.json

OpenAPI 3.1.0 specification for this API. [View](/openapi.json)
