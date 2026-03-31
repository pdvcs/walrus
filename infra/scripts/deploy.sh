#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Walrus deploy script
# Required env vars:
#   TF_VAR_project_id          - GCP project ID
#   TF_VAR_gcs_bucket_name     - GCS artifact bucket name
#   TF_VAR_cloud_sql_db_password - Cloud SQL walrus user password
#   TERRAFORM_STATE_BUCKET     - GCS bucket for Terraform state
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TF_DIR="${REPO_ROOT}/infra/terraform"

# --- Prerequisite checks ---
for cmd in gcloud docker terraform npm; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found in PATH" >&2
    exit 1
  fi
done

for var in TF_VAR_project_id TF_VAR_gcs_bucket_name TF_VAR_cloud_sql_db_password TERRAFORM_STATE_BUCKET; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: required env var '$var' is not set" >&2
    exit 1
  fi
done

PROJECT_ID="${TF_VAR_project_id}"
REGION="${TF_VAR_region:-us-central1}"
IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/walrus/walrus-api"
GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
export TF_VAR_image_tag="${GIT_SHA}"

echo "==> Phase 1: TypeScript build"
npm --prefix "${REPO_ROOT}" run build

echo "==> Phase 2: Ensure Terraform state bucket exists"
if ! gcloud storage buckets describe "gs://${TERRAFORM_STATE_BUCKET}" --project="${PROJECT_ID}" &>/dev/null; then
  gcloud storage buckets create "gs://${TERRAFORM_STATE_BUCKET}" \
    --project="${PROJECT_ID}" \
    --location="${REGION}" \
    --uniform-bucket-level-access
fi

echo "==> Phase 3: Ensure Artifact Registry repo exists"
terraform -chdir="${TF_DIR}" init \
  -backend-config="bucket=${TERRAFORM_STATE_BUCKET}" \
  -reconfigure
terraform -chdir="${TF_DIR}" apply -auto-approve \
  -target=google_artifact_registry_repository.walrus

echo "==> Phase 4: Docker build & push (tag: ${GIT_SHA})"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
docker build -t "${IMAGE_BASE}:${GIT_SHA}" -t "${IMAGE_BASE}:latest" "${REPO_ROOT}"
docker push "${IMAGE_BASE}:${GIT_SHA}"
docker push "${IMAGE_BASE}:latest"

echo "==> Phase 4b: Deploy new image to Cloud Run (if service exists)"
if gcloud run services describe walrus-api --region="${REGION}" --project="${PROJECT_ID}" &>/dev/null; then
  gcloud run services update walrus-api \
    --image="${IMAGE_BASE}:${GIT_SHA}" \
    --region="${REGION}" \
    --project="${PROJECT_ID}"
fi

echo "==> Phase 5: Populate DATABASE_URL secret"
INSTANCE_CONNECTION_NAME="${PROJECT_ID}:${REGION}:walrus-postgres"
DATABASE_URL="postgresql://walrus:${TF_VAR_cloud_sql_db_password}@/walrus?host=/cloudsql/${INSTANCE_CONNECTION_NAME}"

if gcloud secrets describe walrus-database-url --project="${PROJECT_ID}" &>/dev/null; then
  echo "${DATABASE_URL}" | gcloud secrets versions add walrus-database-url \
    --project="${PROJECT_ID}" --data-file=-
else
  echo "${DATABASE_URL}" | gcloud secrets create walrus-database-url \
    --project="${PROJECT_ID}" --data-file=-
fi

echo "==> Phase 6: Terraform apply (full)"
# Import the secret if it exists outside Terraform state (e.g. first deploy)
if ! terraform -chdir="${TF_DIR}" state show google_secret_manager_secret.database_url &>/dev/null; then
  terraform -chdir="${TF_DIR}" import \
    google_secret_manager_secret.database_url \
    "projects/${PROJECT_ID}/secrets/walrus-database-url" || true
fi

terraform -chdir="${TF_DIR}" apply -auto-approve

echo ""
echo "Deploy complete."
terraform -chdir="${TF_DIR}" output cloud_run_url
