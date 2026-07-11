<h1>
<p align="center">
  <img src="./engineering/docs/logo.webp" alt="Logo" width="128">
  <br>Walrus
</p>
</h1>

A configuration-driven package ingress engine. It discovers, caches, and serves software package binaries — so that adding a new package requires only a TOML config file, not code.

**Stack:** Node.js 24 + TypeScript, Express, PostgreSQL, GCS (prod) / local filesystem (dev).

## Quick start

```bash
npm install
createdb walrus && createuser walrus
# create .env.secrets with WALRUS_DEV_DB_PASSWORD=yourpassword
npm run migrate
npm run dev        # http://localhost:8080
```

## Adding a package

Create `packages/walrus-{name}.toml` and validate it:

```bash
npm run validate -- packages/walrus-mytool.toml
```

No code changes needed. See [engineering/docs/package-config.md](engineering/docs/package-config.md) for the full config reference.

You can also validate interactively online at the `/admin/v1/validate` endpoint.

## Documentation

| Doc                                                                      | Contents                                                    |
| ------------------------------------------------------------------------ | ----------------------------------------------------------- |
| [engineering/docs/design.md](engineering/docs/design.md)                 | Architecture, discovery engine, database schema, API design |
| [engineering/docs/package-config.md](engineering/docs/package-config.md) | How to write a TOML package config                          |
| [engineering/docs/build-release.md](engineering/docs/build-release.md)   | Dev setup, building, testing                                |
| [engineering/docs/development.md](engineering/docs/development.md)       | Common commands, development scenarios, env vars            |

API docs are served at `http://localhost:8080/api` (human-readable) and `http://localhost:8080/openapi.json` (OpenAPI 3.1).

## Vulnerability intelligence

Walrus can answer _"does {product} version {X} have known CVEs?"_ for the packages it tracks, and
— its headline feature — cross-reference CVEs against the versions it actually caches. Enable it
for a package by adding a `[vulnerabilities]` section to its TOML (CPE pairs, optional OSV
mapping, aliases); see [package-config.md](engineering/docs/package-config.md).

- `GET /api/v1/vulns?product=&version=` — resolve a name/alias and list known CVEs.
- `GET /api/v1/vulns/products/search?q=` — autocomplete.
- `GET /api/v1/vulns/products/:name` — vulnerability metadata, aliases, CPEs, and CVE count.
- `GET /api/v1/cves/:cveId` — CVE detail.
- `GET /api/v1/packages/:name/vulns` — CVEs affecting each cached version.
- Admin explorer + per-version CVE badges at `/admin/v1/vulns`.

Data is ingested from NVD, CISA KEV, and OSV via external cron (`/internal/vuln-sync/:source`)
plus a one-time `npm run vuln:backfill` — see the ops runbook in
[build-release.md](engineering/docs/build-release.md).

> **Disclaimer:** Absence of results does not imply a product/version is safe. Vulnerability data
> comes from public sources (NVD, CISA KEV, OSV) which may lag or be incomplete.
> NVD configuration trees are flattened to vulnerable application CPEs; environment predicates
> (`AND`, `OR`, and `negate`) are not fully evaluated and can cause conservative false positives.

**Attribution:** This product uses data from the NVD API but is not endorsed or certified by the
NVD. Exploited-in-the-wild data from the CISA Known Exploited Vulnerabilities Catalog (public
domain). Cross-check data from [OSV](https://osv.dev) (Google, Apache-2.0).
