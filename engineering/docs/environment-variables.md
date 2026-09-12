# Reference: Environment variables

Every variable an operator can set, what it defaults to, and what breaks if it is wrong.

## How configuration is loaded

`src/config/index.ts` declares a Zod schema and parses `process.env` against it **once, at
import time**. A value that fails the schema prints the parse error and exits the process with
status 1 — walrus does not start on invalid configuration, in any environment.

Two consequences worth knowing:

- Everything is a string in the environment. Numeric variables are coerced (`z.coerce.number()`),
  so `PORT=abc` is a startup failure, not a silent zero.
- Defaults live in that schema, not in Terraform or the Dockerfile. Anything below marked `—`
  is genuinely optional and unset by default.

### The `Zod` column

Every variable below is declared in the schema, so the column says how much the schema
actually checks — which is a different question:

| Mark | Meaning                                                                                                                                                                                              |
| ---- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `✓`  | Declared with a type, enum, or range. A malformed value fails the parse and stops the process.                                                                                                       |
| `~`  | Declared, but as a free-form string (`z.string()`): it is read and defaulted, and **every** value passes. A typo here is silent. The two credentials additionally normalise an empty value to unset. |

29 variables are `✓` and 17 are `~`. Several `~` entries do have real constraints — a session
key must be 32 bytes, `GCS_BUCKET` must exist when the backend is GCS — but those are enforced
by hand after the parse, not by Zod; see [Boot-time validation](#boot-time-validation).

## Process and logging

| Variable    | Zod | Default       | Description                                                                                                                                                                                    |
| ----------- | --- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PORT`      | ✓   | `8080`        | HTTP listen port.                                                                                                                                                                              |
| `NODE_ENV`  | ✓   | `development` | `development`, `production`, or `test`. Gates several production-only requirements listed under [Boot-time validation](#boot-time-validation), and selects pretty log output in `development`. |
| `LOG_LEVEL` | ✓   | `info`        | `trace`, `debug`, `info`, `warn`, `error`, or `fatal`.                                                                                                                                         |

## Database

| Variable       | Zod | Default | Description                                                                                                                                                                                                              |
| -------------- | --- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `DATABASE_URL` | ~   | —       | Postgres connection string. Unparsed: a malformed URL surfaces as a connection failure, not a config error.                                                                                                              |
| `DB_POOL_MAX`  | ✓   | `5`     | Connections this process may hold. Half of a budget: every workload multiplies it and Cloud SQL's `max_connections` divides it. Terraform sets it per workload in `cloudrun.tf`; read that arithmetic before raising it. |

## Storage

| Variable                 | Zod | Default            | Description                                                                                                                                                                                                                                                                                   |
| ------------------------ | --- | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `STORAGE_BACKEND`        | ✓   | `local`            | `local` or `gcs`.                                                                                                                                                                                                                                                                             |
| `LOCAL_STORAGE_PATH`     | ~   | `./data/artifacts` | Root directory for the `local` backend.                                                                                                                                                                                                                                                       |
| `GCS_BUCKET`             | ~   | —                  | Bucket name. Required when `STORAGE_BACKEND=gcs`, but that requirement is checked at storage init rather than by the schema.                                                                                                                                                                  |
| `GCS_UPLOAD_CHUNK_BYTES` | ✓   | `8388608` (8 MiB)  | Resumable-upload chunk size. Setting it at all is what makes an upload resumable rather than a single unresumable PUT. Costs one buffer of this size per concurrent upload, so resident cost is this × `DOWNLOAD_CONCURRENCY`. Must be a multiple of 256 KiB — enforced by a schema `refine`. |

## GCP

| Variable            | Zod | Default       | Description                                                                                                                                                                                                                                    |
| ------------------- | --- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GCP_PROJECT`       | ~   | —             | Project ID. Required, with `GCP_REGION`, to launch either job below.                                                                                                                                                                           |
| `GCP_REGION`        | ~   | `us-central1` | Region used to address Cloud Run jobs.                                                                                                                                                                                                         |
| `VULN_BACKFILL_JOB` | ~   | —             | Name of the Cloud Run job the API service executes for per-package CVE backfill.                                                                                                                                                               |
| `SYNC_JOB`          | ~   | —             | Name of the Cloud Run job `CloudRunSyncLauncher` executes for an admin-triggered single-package sync, in place of running it in-process where Cloud Run's CPU throttling would starve it once the triggering request's response has been sent. |

## Sync and downloads

| Variable                    | Zod | Default             | Description                                                                                                                                                                                                                                                                                                                                                                       |
| --------------------------- | --- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SYNC_CONCURRENCY`          | ✓   | `4`                 | Packages synced in parallel.                                                                                                                                                                                                                                                                                                                                                      |
| `DOWNLOAD_CONCURRENCY`      | ✓   | `2`                 | Parallel downloads per package.                                                                                                                                                                                                                                                                                                                                                   |
| `TRANSFORM_CONCURRENCY`     | ✓   | `2`                 | Artifacts being transformed at once, governed separately from downloads: a download is IO-bound, a transform is CPU-bound and holds live compression state. Do not raise `DOWNLOAD_CONCURRENCY` to compensate — they limit different resources. Minimum 1.                                                                                                                        |
| `DOWNLOAD_MAX_ATTEMPTS`     | ✓   | `2`                 | Whole-transfer attempts per artifact. The GCS half retries its own chunks, so an outer restart only re-covers the upstream fetch. Minimum 1.                                                                                                                                                                                                                                      |
| `DOWNLOAD_STALL_TIMEOUT_MS` | ✓   | `30000`             | Aborts an artifact fetch that goes fully quiet for this long. The timer rearms when the response starts and on every chunk, so it bounds silence rather than total duration — a slow but still-flowing multi-GB transfer is left alone, while a stalled one releases the package's sync lock. Replaces a flat whole-request timeout, which cannot distinguish the two. Minimum 1. |
| `RANGE_REQUIRED_BYTES`      | ✓   | `1000000000` (1 GB) | Above this size an unranged GET is refused rather than served. Cloud Run caps a request at 3600s, so a client sustaining 2 Mbps gets about 900 MB before the request is killed with no resumable partial.                                                                                                                                                                         |
| `SUGGESTED_CHUNK_BYTES`     | ✓   | `33554432` (32 MiB) | Chunk size advertised in that refusal body. A hint only; the server never constrains the client's actual chunk size.                                                                                                                                                                                                                                                              |

## Discovery HTTP

| Variable                             | Zod | Default | Description                                |
| ------------------------------------ | --- | ------- | ------------------------------------------ |
| `DISCOVERY_HTTP_TIMEOUT_MS`          | ✓   | `15000` | Per-request timeout for version discovery. |
| `DISCOVERY_HTTP_MAX_RETRIES`         | ✓   | `2`     | Retries per discovery request.             |
| `DISCOVERY_HTTP_RETRY_BASE_DELAY_MS` | ✓   | `300`   | Base delay for discovery backoff.          |

## Vulnerability ingestion

| Variable                       | Zod | Default  | Description                                                                                                                                                                                                                                                                                                           |
| ------------------------------ | --- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `VULN_HTTP_TIMEOUT_MS`         | ✓   | `30000`  | Request timeout for the KEV and OSV feeds. Bounds the whole exchange, body read included.                                                                                                                                                                                                                             |
| `VULN_NVD_HTTP_TIMEOUT_MS`     | ✓   | `120000` | The same, for NVD only, which needs far longer: its pages are megabytes and a 30s ceiling demanded roughly 350 KB/s sustained. Sized against Cloud Scheduler's 1800s attempt deadline — the client makes up to 6 attempts per page, so a fully failing page costs about 790s. Redo that arithmetic before raising it. |
| `VULN_NVD_PAGE_SIZE`           | ✓   | `100`    | Rows per page on the steady-state incremental walk. Not the 2000-row API maximum: a recent `lastMod` window holds a few hundred CVEs at roughly 14.5 KB each, so 2000 rows would deliver the whole window as one 10–13 MB body on a single deadline.                                                                  |
| `VULN_NVD_BOOTSTRAP_PAGE_SIZE` | ✓   | `2000`   | Rows per page for the fresh-database bootstrap only. The opposite trade, because the workload inverts: that 119-day window is roughly 372,000 CVEs averaging 2.1 KB, so request count binds rather than body size. At 100 rows the rate-limit floor alone exceeds the attempt deadline.                               |
| `VULN_AUTO_BACKFILL`           | ✓   | `true`   | `true` or `false` literally — not any truthy string, because `Boolean("false")` is `true` and that would make the off switch a no-op. Disables only the autostart sweep; scheduled NVD/KEV/OSV/CVSS ingestion is unaffected.                                                                                          |

## Upstream credentials

Both are optional. walrus runs without them, which is what makes local development and CI
possible with nothing provisioned. In a deployment their absence is almost always an oversight,
and the only symptom is reduced throughput.

| Variable       | Zod | Default | Description                                                                                                                                                                                                                                                                                                                        |
| -------------- | --- | ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NVD_API_KEY`  | ~   | —       | Raises NVD's published rate limit from 5 to 50 requests per 30s (walrus uses 4 and 45, staying one under). Unset, ingestion runs roughly ten times longer and is far likelier to be cut off by the scheduler's attempt deadline — and a cut-off run ingests nothing. Empty is normalised to unset.                                 |
| `GITHUB_TOKEN` | ~   | —       | Raises api.github.com from 60 to 5,000 requests per hour. Unset, discovery for `github-releases` packages is throttled per IP, and Cloud Run's egress address is shared with other tenants, so that budget can be exhausted by strangers. A fine-grained PAT with public read-only access is enough. Empty is normalised to unset. |

Neither is reported as a degradation: a standing configuration choice is not machinery that has
stopped, so it would leave the admin banner permanently visible. Instead each process logs a
warning once at startup, and `GET /app/status` reports `upstream_credentials.nvd_api_key` as its
own object. See `src/common/upstream-credentials.ts`.

## Authentication and sessions

| Variable                         | Zod | Default              | Description                                                                                                                                                                                                                                       |
| -------------------------------- | --- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WALRUS_AUTHN_PROVIDER`          | ~   | `password`           | `password`, or a path to a provider module (relative to the working directory, or absolute). Any other value throws after the parse, not during it.                                                                                               |
| `WALRUS_ADMIN_PASSWORD`          | ~   | —                    | Password for the built-in `password` provider.                                                                                                                                                                                                    |
| `WALRUS_ADMINS_FILE`             | ~   | `config/admins.toml` | Path to the admin roster.                                                                                                                                                                                                                         |
| `WALRUS_ADMIN_MATCH`             | ✓   | `fold`               | How roster identities are matched: `fold` (case-insensitive) or `exact`.                                                                                                                                                                          |
| `WALRUS_SESSION_SECRET`          | ~   | —                    | HMAC key for session cookies. At least 32 bytes, checked after the parse. Unset outside production, a random process-local key is generated and warned about — unsuitable for more than one instance, since sessions will not verify across them. |
| `WALRUS_SESSION_SECRET_PREVIOUS` | ~   | —                    | Previous key, accepted during rotation. At least 32 bytes, checked after the parse.                                                                                                                                                               |
| `WALRUS_SESSION_TTL_SECONDS`     | ✓   | `7200` (2h)          | Idle session lifetime.                                                                                                                                                                                                                            |
| `WALRUS_SESSION_MAX_SECONDS`     | ✓   | `28800` (8h)         | Absolute session lifetime. Must be at least the TTL — checked after the parse, since Zod cannot compare two fields here.                                                                                                                          |
| `WALRUS_SESSION_EPOCH`           | ✓   | `0`                  | Increment to invalidate every existing session at once.                                                                                                                                                                                           |

## Machine (internal) authentication

| Variable                          | Zod | Default | Description                                     |
| --------------------------------- | --- | ------- | ----------------------------------------------- |
| `WALRUS_INTERNAL_AUDIENCE`        | ~   | —       | Expected OIDC audience on `/internal` requests. |
| `WALRUS_INTERNAL_SERVICE_ACCOUNT` | ~   | —       | Service account allowed to call `/internal`.    |

Both are required in production. Unset outside it, `/internal` fails closed with 503 rather than
opening up — so scheduled ingestion will not run locally without them.

## Enterprise egress

| Variable              | Zod | Default                    | Description                                                                                                                                                             |
| --------------------- | --- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WALRUS_EGRESS_RULES` | ~   | `config/egress-rules.toml` | Path to the rewrite-rule file. Ships empty, so this changes nothing out of the box. Rule _contents_ are validated separately at boot; the schema only takes a path.     |
| `WALRUS_EGRESS_MODE`  | ✓   | `direct`                   | `direct` (configured rules still apply to matching URLs), `rules` (an unmatched URL is logged at warn and attempted anyway), or `strict` (an unmatched URL is refused). |

See [enterprise.md](enterprise.md) for the rule file format and the full design.

## Adopter deployment: base path

| Variable           | Zod | Default | Description                                                                                                                                                                                                                                                                                                                                                  |
| ------------------ | --- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `WALRUS_BASE_PATH` | ✓   | `""`    | Serves the whole app under this path prefix instead of `/` — e.g. `/foo` rather than `/`. Priority is a single path segment; a multi-segment prefix (`/corp/walrus`) is accepted by the same pattern. Must start with `/`, no trailing slash, not `/` alone, no doubled `/` — enforced by a schema `refine`. Default is empty, today's unprefixed behaviour. |

See [enterprise.md](enterprise.md#serving-under-a-path-prefix-walrus_base_path) for what gets
prefixed and the `/health` carve-out for Cloud Run's own probe.

## Adopter branding

| Variable          | Zod | Default  | Description                                                                                                                                                                                            |
| ----------------- | --- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `WALRUS_BRANDING` | ✓   | `Walrus` | Product name shown as the big heading and browser title of the public landing page. Free text, trimmed, and must be non-empty; escaped at render time. The small top-left nav wordmark stays `Walrus`. |

Only the landing page is branded: it is the page an adopter's own users see first, while the
nav wordmark and `Walrus Admin` titles identify the software itself.

## Boot-time validation

These fail startup rather than degrading, so they surface immediately rather than at first use.
Everything below the first row is a hand-written check that runs _after_ the schema parse — which
is why the variables involved are marked `~` above rather than `✓`:

| Condition                                                              | Result                      |
| ---------------------------------------------------------------------- | --------------------------- |
| Any `✓` variable failing its schema type or range                      | Parse error printed, exit 1 |
| `GCS_UPLOAD_CHUNK_BYTES` not a multiple of 256 KiB                     | Parse error, exit 1         |
| `STORAGE_BACKEND=gcs` with no `GCS_BUCKET`                             | Throws at storage init      |
| `WALRUS_SESSION_SECRET` shorter than 32 bytes                          | Throws                      |
| `WALRUS_SESSION_SECRET` unset while `NODE_ENV=production`              | Throws                      |
| `WALRUS_SESSION_SECRET_PREVIOUS` shorter than 32 bytes                 | Throws                      |
| `WALRUS_SESSION_MAX_SECONDS` below `WALRUS_SESSION_TTL_SECONDS`        | Throws                      |
| Internal audience or service account unset while `NODE_ENV=production` | Throws                      |
| `WALRUS_AUTHN_PROVIDER` naming neither `password` nor a module         | Throws                      |

## Which workload reads what

The three deployed workloads run the same image with different entrypoints, and Terraform mounts
credentials only where they are used:

| Workload               | Entrypoint                           | Credentials mounted           |
| ---------------------- | ------------------------------------ | ----------------------------- |
| `walrus-api`           | the HTTP server                      | `NVD_API_KEY`                 |
| `walrus-sync`          | `dist/commands/sync-job.js`          | `NVD_API_KEY`, `GITHUB_TOKEN` |
| `walrus-vuln-backfill` | `dist/commands/vuln-backfill-job.js` | `NVD_API_KEY`                 |

`GITHUB_TOKEN` is mounted **only** into `walrus-sync`, because that is where scheduled package
discovery runs. Its absence from the API service is correct, not drift — which is why
`/app/status` does not report on it.

## Deploy-time variables

These are read by `infra/scripts/deploy.sh` and Terraform, not by the application, so none of
them reach the Zod schema at all — `deploy.sh` checks the required ones itself and exits if any
is empty. They are listed here because an operator sets them in the same shell.

| Variable                         | Required | Description                                                                     |
| -------------------------------- | -------- | ------------------------------------------------------------------------------- |
| `TF_VAR_project_id`              | yes      | GCP project ID.                                                                 |
| `TF_VAR_gcs_bucket_name`         | yes      | Artifact bucket name.                                                           |
| `TF_VAR_cloud_sql_db_password`   | yes      | Cloud SQL `walrus` user password.                                               |
| `TERRAFORM_STATE_BUCKET`         | yes      | GCS bucket holding Terraform state.                                             |
| `WALRUS_SESSION_SECRET`          | yes      | At least 32 bytes; written to Secret Manager.                                   |
| `WALRUS_ADMIN_PASSWORD`          | yes      | At least 16 bytes; written to Secret Manager.                                   |
| `NVD_API_KEY`                    | no       | Written to Secret Manager when set. `deploy.sh` prints a notice when it is not. |
| `GITHUB_TOKEN`                   | no       | As above.                                                                       |
| `WALRUS_SESSION_SECRET_PREVIOUS` | no       | Old session key, during rotation.                                               |

Secret names in Secret Manager are `walrus-nvd-api-key`, `walrus-github-token`,
`walrus-session-secret`, `walrus-session-secret-previous`, `walrus-admin-password`, and
`walrus-database-url`.

## Declared but unused

| Variable            | Zod | Note                                                                                                                                                                                                                          |
| ------------------- | --- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `DEFAULT_RETENTION` | ✓   | Parsed by the config schema, then read nowhere. Retention comes from each package's TOML, where `retention.versions_per_group` has its own default of 3 (`src/types/package-config.ts`). Setting this variable has no effect. |
