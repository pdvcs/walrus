#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Walrus deploy script
# Required env vars:
#   TF_VAR_project_id          - GCP project ID
#   TF_VAR_gcs_bucket_name     - GCS artifact bucket name
#   TF_VAR_cloud_sql_db_password - Cloud SQL walrus user password
#   WALRUS_SESSION_SECRET      - HMAC session key (at least 32 bytes)
#   WALRUS_ADMIN_PASSWORD      - built-in admin password (at least 16 bytes)
#   TERRAFORM_STATE_BUCKET     - GCS bucket for Terraform state
# Optional env vars:
#   NVD_API_KEY                - upstream NVD API 2.0 key (WAL-92). Absent, the deployment runs
#                                keyless at NVD's 5 req/30s instead of 50: slower ingestion, and
#                                a historical backfill measured in hours rather than minutes.
#                                Never required, so a fresh project can bootstrap without one.
#   WALRUS_SESSION_SECRET_PREVIOUS - old session key during rotation
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

for var in TF_VAR_project_id TF_VAR_gcs_bucket_name TF_VAR_cloud_sql_db_password WALRUS_SESSION_SECRET WALRUS_ADMIN_PASSWORD TERRAFORM_STATE_BUCKET; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: required env var '$var' is not set" >&2
    exit 1
  fi
done

# Keep the address out of Terraform source. A project with exactly one human owner needs no
# extra deploy configuration; shared projects must opt in with TF_VAR_alert_notification_email.
if [[ -z "${TF_VAR_alert_notification_email:-}" ]]; then
  mapfile -t WALRUS_PROJECT_OWNERS < <(
    gcloud projects get-iam-policy "${TF_VAR_project_id}" \
      --flatten="bindings[].members" \
      --filter='bindings.role=roles/owner AND bindings.members:user:' \
      --format='value(bindings.members)' | sed 's/^user://'
  )
  if (( ${#WALRUS_PROJECT_OWNERS[@]} != 1 )); then
    echo "ERROR: set TF_VAR_alert_notification_email; project does not have exactly one user owner" >&2
    exit 1
  fi
  export TF_VAR_alert_notification_email="${WALRUS_PROJECT_OWNERS[0]}"
fi

if (( ${#WALRUS_SESSION_SECRET} < 32 )); then
  echo "ERROR: WALRUS_SESSION_SECRET must be at least 32 bytes" >&2
  exit 1
fi
if (( ${#WALRUS_ADMIN_PASSWORD} < 16 )); then
  echo "ERROR: WALRUS_ADMIN_PASSWORD must be at least 16 bytes" >&2
  exit 1
fi

PROJECT_ID="${TF_VAR_project_id}"
REGION="${TF_VAR_region:-us-central1}"
IMAGE_BASE="${REGION}-docker.pkg.dev/${PROJECT_ID}/walrus/walrus-api"
GIT_SHA="$(git -C "${REPO_ROOT}" rev-parse --short HEAD)"
export TF_VAR_image_tag="${GIT_SHA}"

# The NVD key is optional, but Cloud Run refuses to start a revision that references a secret
# with no versions — so Terraform must know whether one was populated before it wires the
# secret_key_ref. Derived from the environment rather than exposed as a second operator switch,
# which could disagree with what this script actually put in Secret Manager below.
if [[ -n "${NVD_API_KEY:-}" ]]; then
  export TF_VAR_nvd_api_key_configured="true"
else
  export TF_VAR_nvd_api_key_configured="false"
  echo "NOTE: NVD_API_KEY is not set — deploying keyless. NVD ingestion is rate-limited to" >&2
  echo "      5 req/30s (vs 50 with a key); set it and re-run to enable the higher limit." >&2
fi

echo "==> Phase 1: TypeScript build"
npm --prefix "${REPO_ROOT}" run build

echo "==> Phase 2: Ensure Terraform state bucket exists"
if ! gcloud storage buckets describe "gs://${TERRAFORM_STATE_BUCKET}" --project="${PROJECT_ID}" &>/dev/null; then
  # Versioned: this bucket is the only record of the whole deployment, and a truncated or
  # corrupted state write is otherwise unrecoverable (WAL-40, 2026-08-30).
  gcloud storage buckets create "gs://${TERRAFORM_STATE_BUCKET}" \
    --project="${PROJECT_ID}" \
    --location="${REGION}" \
    --uniform-bucket-level-access
  # `gcloud storage buckets create` has no versioning flag; enable it immediately
  # afterwards so the remote Terraform state is recoverable from a bad write.
  gcloud storage buckets update "gs://${TERRAFORM_STATE_BUCKET}" \
    --project="${PROJECT_ID}" \
    --versioning
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

echo "==> Phase 5: Populate runtime secrets"
INSTANCE_CONNECTION_NAME="${PROJECT_ID}:${REGION}:walrus-postgres"
DATABASE_URL="postgresql://walrus:${TF_VAR_cloud_sql_db_password}@/walrus?host=/cloudsql/${INSTANCE_CONNECTION_NAME}"
PREVIOUS_SESSION_SECRET="${WALRUS_SESSION_SECRET_PREVIOUS:-${WALRUS_SESSION_SECRET}}"

populate_secret() {
  local secret_name="$1"
  local secret_value="$2"
  if gcloud secrets describe "${secret_name}" --project="${PROJECT_ID}" &>/dev/null; then
    printf '%s' "${secret_value}" | gcloud secrets versions add "${secret_name}" \
      --project="${PROJECT_ID}" --data-file=-
  else
    printf '%s' "${secret_value}" | gcloud secrets create "${secret_name}" \
      --project="${PROJECT_ID}" --data-file=-
  fi
}

populate_secret walrus-database-url "${DATABASE_URL}"
populate_secret walrus-session-secret "${WALRUS_SESSION_SECRET}"
populate_secret walrus-session-secret-previous "${PREVIOUS_SESSION_SECRET}"
populate_secret walrus-admin-password "${WALRUS_ADMIN_PASSWORD}"
# Optional (WAL-92 AC4): only add a version when a key was supplied. An empty version would be
# worse than none — the workloads would mount a blank apiKey header rather than fall back to the
# keyless path the client already implements.
if [[ "${TF_VAR_nvd_api_key_configured}" == "true" ]]; then
  populate_secret walrus-nvd-api-key "${NVD_API_KEY}"
fi

echo "==> Phase 6: Terraform apply (full)"
# Import the secret if it exists outside Terraform state (e.g. first deploy)
if ! terraform -chdir="${TF_DIR}" state show google_secret_manager_secret.database_url &>/dev/null; then
  terraform -chdir="${TF_DIR}" import \
    google_secret_manager_secret.database_url \
    "projects/${PROJECT_ID}/secrets/walrus-database-url" || true
fi
if ! terraform -chdir="${TF_DIR}" state show google_secret_manager_secret.session_secret &>/dev/null; then
  terraform -chdir="${TF_DIR}" import \
    google_secret_manager_secret.session_secret \
    "projects/${PROJECT_ID}/secrets/walrus-session-secret" || true
fi
if ! terraform -chdir="${TF_DIR}" state show google_secret_manager_secret.session_secret_previous &>/dev/null; then
  terraform -chdir="${TF_DIR}" import \
    google_secret_manager_secret.session_secret_previous \
    "projects/${PROJECT_ID}/secrets/walrus-session-secret-previous" || true
fi
if ! terraform -chdir="${TF_DIR}" state show google_secret_manager_secret.admin_password &>/dev/null; then
  terraform -chdir="${TF_DIR}" import \
    google_secret_manager_secret.admin_password \
    "projects/${PROJECT_ID}/secrets/walrus-admin-password" || true
fi
# Only when populated above: keyless, the secret has never been created outside Terraform, and
# the apply below creates the (versionless) resource itself.
if [[ "${TF_VAR_nvd_api_key_configured}" == "true" ]] &&
  ! terraform -chdir="${TF_DIR}" state show google_secret_manager_secret.nvd_api_key &>/dev/null; then
  terraform -chdir="${TF_DIR}" import \
    google_secret_manager_secret.nvd_api_key \
    "projects/${PROJECT_ID}/secrets/walrus-nvd-api-key" || true
fi

terraform -chdir="${TF_DIR}" apply -auto-approve

echo "==> Phase 7: Deploy new image to Cloud Run"
# Apply the secret references and OIDC configuration before starting an image whose production
# boot checks require them. On a first deployment Terraform already used this image; update is
# harmless and keeps the lifecycle-ignore image workflow consistent on later deployments.
gcloud run services update walrus-api \
  --image="${IMAGE_BASE}:${GIT_SHA}" \
  --region="${REGION}" \
  --project="${PROJECT_ID}"

echo ""
echo "Deploy complete."
terraform -chdir="${TF_DIR}" output cloud_run_url
