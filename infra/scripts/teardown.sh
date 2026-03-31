#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="${SCRIPT_DIR}/../terraform"

# --- Prerequisite checks ---
for cmd in gcloud terraform; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found in PATH" >&2
    exit 1
  fi
done

for var in TF_VAR_project_id TERRAFORM_STATE_BUCKET; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: required env var '$var' is not set" >&2
    exit 1
  fi
done

PROJECT_ID="${TF_VAR_project_id}"
REGION="${TF_VAR_region:-us-central1}"

echo "WARNING: This will destroy all Walrus GCP resources."
echo "The GCS artifact bucket and Terraform state bucket will NOT be deleted."
echo ""
read -rp "Type 'destroy' to confirm: " CONFIRM
if [[ "${CONFIRM}" != "destroy" ]]; then
  echo "Aborted."
  exit 1
fi

echo "==> Terraform init"
terraform -chdir="${TF_DIR}" init \
  -backend-config="bucket=${TERRAFORM_STATE_BUCKET}" \
  -reconfigure

echo "==> Disabling deletion protection and enabling force-destroy"
terraform -chdir="${TF_DIR}" apply -auto-approve \
  -target=google_sql_database_instance.walrus \
  -target=google_storage_bucket.artifacts \
  -var="sql_deletion_protection=false" \
  -var="gcs_force_destroy=true"

echo "==> Terraform destroy"
terraform -chdir="${TF_DIR}" destroy -auto-approve \
  -var="sql_deletion_protection=false" \
  -var="gcs_force_destroy=true"

echo ""
echo "Teardown complete."
echo ""
echo "NOTE: The following resources were NOT deleted and require manual cleanup if desired:"
echo "  - Terraform state bucket: gs://${TERRAFORM_STATE_BUCKET}"
echo "  - GCS artifact bucket:    gs://${TF_VAR_gcs_bucket_name:-<TF_VAR_gcs_bucket_name>}"
echo "  - Artifact Registry images (in the 'walrus' repository)"
