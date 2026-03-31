<h1>
<p align="center">
  <img src="./docs/logo.webp" alt="Logo" width="128">
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

No code changes needed. See [docs/package-config.md](docs/package-config.md) for the full config reference.

You can also validate interactively online at the `/admin/v1/validate` endpoint.


## Documentation

| Doc | Contents |
| --- | -------- |
| [docs/design.md](docs/design.md) | Architecture, discovery engine, database schema, API design |
| [docs/package-config.md](docs/package-config.md) | How to write a TOML package config |
| [docs/build-release.md](docs/build-release.md) | Dev setup, building, testing |
| [docs/development.md](docs/development.md) | Common commands, development scenarios, env vars |

API docs are served at `http://localhost:8080/api` (human-readable) and `http://localhost:8080/openapi.json` (OpenAPI 3.1).
