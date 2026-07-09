# Walrus GCP Infrastructure

Deploys Walrus to GCP using Cloud Run, Cloud SQL (Postgres 18), GCS, and Cloud Scheduler.

## Architecture

- **Cloud Run** (min 1 instance) — Walrus API
- **Cloud SQL Postgres 18** — metadata (public IP, IAM-restricted via Auth Proxy)
- **GCS Bucket** — cached binary artifacts
- **Cloud Scheduler** — POSTs `/internal/sync` every 6h (OIDC-authenticated)
- **Artifact Registry** — Docker images
- **Secret Manager** — `walrus-database-url`

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
export TERRAFORM_STATE_BUCKET="your-project-walrus-tf-state"
```

Optional overrides (have defaults):

```bash
export TF_VAR_region="us-central1"          # default: us-central1
export TF_VAR_cloud_sql_tier="db-f1-micro"  # default: db-f1-micro (~$7/month)
export TF_VAR_cloud_run_min_instances="1"   # default: 1 (always-on)
export TF_VAR_sync_schedule="0 */6 * * *"   # default: every 6 hours UTC
```

## Deploy

```bash
bash infra/scripts/deploy.sh
```

The script:

1. Runs `npm run build`
2. Builds and pushes a Docker image tagged with the current git SHA
3. Populates the `walrus-database-url` secret in Secret Manager
4. Runs `terraform apply` to provision/update all GCP resources

## Teardown

```bash
bash infra/scripts/teardown.sh
```

Prompts for confirmation, disables Cloud SQL deletion protection, then runs `terraform destroy`.

> **Note:** The Terraform state bucket and GCS artifact bucket are **not** deleted automatically (`force_destroy = false`). Delete them manually if desired.

## Security notes

- `/admin/v1/` routes are publicly reachable (no authentication in the current codebase). Consider adding auth before exposing this service to the internet.
- Cloud SQL uses IAM-only access; no authorized networks are required.
- The `walrus-api` service account has minimal permissions: GCS Object Admin on the artifact bucket, Cloud SQL Client, and Secret Accessor for the DB URL.

## Cost estimate (no VPC/NAT)

| Resource                           | ~Monthly cost     |
| ---------------------------------- | ----------------- |
| Cloud SQL `db-f1-micro`            | ~$7               |
| Cloud Run (min 1 instance, 512 MB) | ~$5–15            |
| GCS, Artifact Registry, Scheduler  | negligible        |
| **Total**                          | **~$15–25/month** |
