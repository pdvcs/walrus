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
echo "This INCLUDES the GCS artifact bucket and every object in it: the bucket is a Terraform"
echo "resource, and the destroy below passes gcs_force_destroy=true. Only the Terraform state"
echo "bucket survives, because it is the backend rather than a managed resource."
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

# Terraform requires a value for every declared variable, destroy included, and these two are set
# only by deploy.sh — so teardown aborted on the targeted apply below having touched nothing.
# alert_notification_email is inert here: the notification channel is not a target, and destroy
# never sends the value anywhere. image_tag is NOT inert — the apply targets both Cloud Run Jobs,
# so a value that disagrees with what is deployed would rewrite their image instead of only
# lowering deletion protection. Read it back off the running job.
export TF_VAR_alert_notification_email="${TF_VAR_alert_notification_email:-teardown@example.invalid}"

if [[ -z "${TF_VAR_image_tag:-}" ]]; then
  # An absent job means a previous run already removed it, leaving the apply nothing to target;
  # any placeholder then does, so long as it parses.
  DEPLOYED_IMAGE="$(gcloud run jobs describe walrus-sync \
    --project="${PROJECT_ID}" --region="${REGION}" \
    --format='value(spec.template.spec.template.spec.containers[0].image)' 2>/dev/null || true)"
  TF_VAR_image_tag="${DEPLOYED_IMAGE##*:}"
  export TF_VAR_image_tag="${TF_VAR_image_tag:-teardown}"
fi

echo "==> Disabling deletion protection and enabling force-destroy"
terraform -chdir="${TF_DIR}" apply -auto-approve \
  -target=google_sql_database_instance.walrus \
  -target=google_storage_bucket.artifacts \
  -target=google_cloud_run_v2_job.sync \
  -target=google_cloud_run_v2_job.vuln_backfill \
  -var="sql_deletion_protection=false" \
  -var="gcs_force_destroy=true" \
  -var="job_deletion_protection=false"

echo "==> Terraform destroy"
terraform -chdir="${TF_DIR}" destroy -auto-approve \
  -var="sql_deletion_protection=false" \
  -var="gcs_force_destroy=true" \
  -var="job_deletion_protection=false"

echo ""
echo "Teardown complete."
echo ""
echo "NOTE: The following resources were NOT deleted and require manual cleanup if desired:"
echo "  - Terraform state bucket: gs://${TERRAFORM_STATE_BUCKET}"
echo "  - Artifact Registry images (in the 'walrus' repository)"
