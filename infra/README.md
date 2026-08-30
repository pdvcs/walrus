# Walrus GCP Infrastructure

Deploys Walrus to GCP using Cloud Run, Cloud SQL (Postgres 18), GCS, and Cloud Scheduler.

## Architecture

- **Cloud Run** (min 1 instance) — Walrus API
- **Cloud SQL Postgres 18** — metadata (public IP, IAM-restricted via Auth Proxy)
- **GCS Bucket** — cached binary artifacts
- **Cloud Scheduler** — executes the `walrus-sync` Cloud Run Job every 6h, plus one job per
  vulnerability
  source (`walrus-vuln-sync-{nvd,kev,osv,cvss}`) on its own cadence (all OIDC-authenticated).
  `cvss` enrichment is scheduled deliberately: it can newly block downloads, and here that is
  the point — see ADR-002.
- **Cloud Run Jobs** — `walrus-sync` (package sync; artifact downloads outlast any request
  deadline) and `walrus-vuln-backfill` (one-time historical CVE ingestion)
- **Artifact Registry** — Docker images
- **Secret Manager** — database URL, built-in admin password, and current/previous session keys

## One-time bootstrap

### 1. Enable GCP APIs

```bash
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  storage.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  cloudscheduler.googleapis.com
```

### 2. Create Terraform state bucket

```bash
gsutil mb gs://{project}-walrus-tf-state
```

### 3. Install Terraform ≥ 1.9

https://developer.hashicorp.com/terraform/install

### 4. Set required environment variables

```bash
export TF_VAR_project_id="your-gcp-project-id"
export TF_VAR_gcs_bucket_name="your-project-walrus-artifacts"
export TF_VAR_cloud_sql_db_password="a-strong-password"
export WALRUS_ADMIN_PASSWORD="a-strong-operator-password"
export WALRUS_SESSION_SECRET="$(openssl rand -base64 48)"
export TERRAFORM_STATE_BUCKET="your-project-walrus-tf-state"
```

Optional overrides (have defaults):

```bash
export TF_VAR_region="us-central1"          # default: us-central1
export TF_VAR_cloud_sql_tier="db-f1-micro"  # default: db-f1-micro (~$7/month)
export TF_VAR_cloud_run_min_instances="1"   # default: 1 (always-on)
export TF_VAR_sync_schedule="0 */6 * * *"   # default: every 6 hours UTC
export TF_VAR_internal_oidc_audience="walrus-internal"
# During key rotation, set this to the old key before changing WALRUS_SESSION_SECRET.
export WALRUS_SESSION_SECRET_PREVIOUS="$WALRUS_SESSION_SECRET"
```

## Deploy

```bash
bash infra/scripts/deploy.sh
```

The script:

1. Runs `npm run build`
2. Builds and pushes a Docker image tagged with the current git SHA
3. Populates database, admin-password, and current/previous session secrets in Secret Manager
4. Runs `terraform apply` to provision/update all GCP resources

## Teardown

```bash
bash infra/scripts/teardown.sh
```

Prompts for confirmation, disables Cloud SQL deletion protection, then runs `terraform destroy`.

> **Note:** The Terraform state bucket and GCS artifact bucket are **not** deleted automatically (`force_destroy = false`). Delete them manually if desired.

## Security notes

- `/admin/v1/` is guarded by provider authentication, the reviewed `config/admins.toml` roster,
  signed sessions, origin checks, throttling, and subject-attributed audit. The built-in password
  provider is a strawman; set `WALRUS_AUTHN_PROVIDER` in a downstream image for an enterprise
  directory implementation.
- `/internal/` verifies Google OIDC signature, the exact `internal_oidc_audience`, expiry, and the
  `walrus-scheduler` service-account principal. The public Cloud Run invoker binding remains
  necessary for `/api/v1`, `/download`, health, and docs; it is not an application authorization
  bypass.
- Cloud SQL uses IAM-only access; no authorized networks are required.
- The `walrus-api` service account has minimal permissions: GCS Object Admin on the artifact bucket,
  Cloud SQL Client, and Secret Accessor for its four runtime secrets.

## Cost estimate (no VPC/NAT)

| Resource                           | ~Monthly cost     |
| ---------------------------------- | ----------------- |
| Cloud SQL `db-f1-micro`            | ~$7               |
| Cloud Run (min 1 instance, 512 MB) | ~$5–15            |
| GCS, Artifact Registry, Scheduler  | negligible        |
| **Total**                          | **~$15–25/month** |
