# Build and Release

## Prerequisites

- **Node.js** 24+
- **npm** (comes with Node)
- **PostgreSQL** installed locally — no Docker needed; the dev setup talks to a native Postgres instance directly

## Setting up a local dev environment

### 1. Install dependencies

```bash
npm install
```

### 2. Create the local database

Run once:

```bash
createdb walrus
createuser walrus
psql -c "ALTER USER walrus WITH PASSWORD 'yourpassword';"
psql -c "GRANT ALL ON SCHEMA public TO walrus;" walrus
```

### 3. Configure environment files

Two files are needed. **`.env.local`** is committed to the repo with safe defaults:

```
DATABASE_URL=postgresql://walrus:${WALRUS_DEV_DB_PASSWORD}@localhost:5432/walrus
STORAGE_BACKEND=local
LOCAL_STORAGE_PATH=./data/artifacts
PORT=8080
NODE_ENV=development
LOG_LEVEL=debug
```

**`.env.secrets`** is _not_ committed — create it in the repo root with your actual DB password:

```
WALRUS_DEV_DB_PASSWORD=yourpassword
```

Both files are loaded together by any `npm run` script that needs database access (`migrate`, `test:integration`, `dev`). You only need `.env.local` for commands that don't touch the database (e.g. `validate`).

### 4. Run migrations

```bash
npm run migrate
```

This applies any pending migration files from `src/db/migrations/`. On a fresh database this creates the five tables: `packages`, `versions`, `artifacts`, `sync_jobs`, `admin_actions`.

The server also runs migrations automatically on `npm run dev` startup via `runMigrations()` in `src/db/client.ts`.

---

## Building

```bash
npm run build
```

Compiles TypeScript to `dist/` via `tsc`. The compiled output targets CommonJS / ES2022. The `main` entrypoint is `dist/main.js`.

---

## Testing

### Unit tests (no database or network required)

```bash
npm run test:unit
```

Runs tests under `tests/common/`, `tests/discovery/`, `tests/services/`, `tests/routes/`, and `tests/storage/`. These use `vitest` with `msw` to mock HTTP and do not require a database connection or real upstream API access.

### Integration tests (require running Postgres)

```bash
npm run test:integration
```

Runs tests under `tests/db/`. These exercise the real database — they connect to the Postgres instance configured in `.env.local` + `.env.secrets`, create tables via migrations, insert and query data, then roll back. Make sure migrations have run at least once first.

### All tests

```bash
npm test
```

Runs both unit and integration test suites.

### Watch mode (during development)

```bash
npx vitest
```

Runs in watch mode, re-running affected tests on file changes.

### Release testing

_Not yet implemented._

---

## Releasing

_Not yet implemented._

---
