#!/usr/bin/env bash
#
# Assert that `infra/scripts/teardown.sh` actually emptied the project (WAL-93).
#
# Written before the teardown it checks, deliberately. WAL-93's manual test is one-shot and
# destructive: the environment exists, then it does not, and whatever nobody thought to look at in
# between is unrecoverable. The 2026-08-30 disposal is the case in point — the script was
# interrupted partway, needed manual Terraform recovery, and the evidence of what it had and had
# not removed is simply gone. That is the same argument `windows-endpoint-test.ps1` made and won:
# a manual test is usually a script someone runs once by hand, so write the script first.
#
# Run it immediately after teardown.sh and keep the output. It asserts the two halves of the
# script's own closing claim — that everything Terraform manages is destroyed, and that exactly
# three things survive on purpose:
#
#   - the Terraform state bucket
#   - the GCS artifact bucket
#   - the Artifact Registry images
#
# The second half matters as much as the first. A teardown that also took the artifact bucket
# would look like a clean success here and be a data-loss incident.
#
#   ./infra/scripts/verify-teardown.sh            # after sourcing ~/.config/walrus/deploy.env
#   ./infra/scripts/verify-teardown.sh --project X
#
# Exit 0 if the project is clean, 1 otherwise. Warnings do not fail the run.

set -uo pipefail

PROJECT="${TF_VAR_project_id:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${TF_VAR_region:-us-central1}"

while [ $# -gt 0 ]; do
  case "$1" in
    --project) PROJECT="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    -h|--help) sed -n '2,27p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$PROJECT" ]; then
  echo "no project: set TF_VAR_project_id or pass --project" >&2
  exit 2
fi

PASS=0; FAIL=0; WARN=0
ok()   { printf '  \033[32mPASS\033[0m  %-9s %s\n' "$1" "$2"; PASS=$((PASS+1)); }
no()   { printf '  \033[31mFAIL\033[0m  %-9s %s\n' "$1" "$2"; FAIL=$((FAIL+1)); }
warn() { printf '  \033[33mWARN\033[0m  %-9s %s\n' "$1" "$2"; WARN=$((WARN+1)); }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

printf 'walrus teardown check — %s (%s)\n' "$PROJECT" "$REGION"

# `gcloud ... list` prints nothing and exits 0 for an empty collection, which is the answer we
# want, but it also prints nothing on a permission error or a bad flag. Every check below counts
# lines from a `--format=value(...)` query, so an auth failure would read as "clean" — hence the
# reachability gate first. Without it this whole script is a machine for printing PASS.
gone() {
  local tag="$1" what="$2" count="$3"
  if [ "${count:-0}" -eq 0 ]; then ok "$tag" "$what: none left"
  else no "$tag" "$what: $count still present"; fi
}

count() { printf '%s\n' "$1" | grep -c . ; }

# =========================================================================================
head_ "Project is reachable"
# =========================================================================================
if gcloud projects describe "$PROJECT" --format='value(projectId)' >/dev/null 2>&1; then
  ok "WAL-93" "project $PROJECT exists and is readable"
else
  echo "  cannot read project $PROJECT — every check below would falsely report 'none left'" >&2
  exit 1
fi

# =========================================================================================
head_ "Compute and jobs — must be gone"
# =========================================================================================
gone "WAL-93" "Cloud Run services" \
  "$(count "$(gcloud run services list --region="$REGION" --project="$PROJECT" --format='value(name)' 2>/dev/null)")"

# The one WAL-93 was actually about: `teardown.sh` could not destroy these at all until the
# `job_deletion_protection` override was added, and it failed *after* lowering the database's
# protection, which is the worst order to fail in.
gone "WAL-93" "Cloud Run jobs" \
  "$(count "$(gcloud run jobs list --region="$REGION" --project="$PROJECT" --format='value(name)' 2>/dev/null)")"

gone "WAL-40" "Cloud Scheduler jobs" \
  "$(count "$(gcloud scheduler jobs list --location="$REGION" --project="$PROJECT" --format='value(name)' 2>/dev/null)")"

# =========================================================================================
head_ "Data and identity — must be gone"
# =========================================================================================
gone "WAL-93" "Cloud SQL instances" \
  "$(count "$(gcloud sql instances list --project="$PROJECT" --format='value(name)' 2>/dev/null)")"

gone "WAL-92" "Secret Manager secrets" \
  "$(count "$(gcloud secrets list --project="$PROJECT" --format='value(name)' 2>/dev/null)")"

SA=$(gcloud iam service-accounts list --project="$PROJECT" \
  --format='value(email)' 2>/dev/null | grep -E 'walrus' || true)
gone "WAL-93" "walrus service accounts" "$(count "$SA")"

ROLES=$(gcloud iam roles list --project="$PROJECT" --format='value(name)' 2>/dev/null | grep -E 'walrus|job_runner|jobRunner' || true)
gone "WAL-99" "custom IAM roles" "$(count "$ROLES")"

# =========================================================================================
head_ "Alerting — must be gone"
# =========================================================================================
# Alert policies outlive the resources they watch and keep emailing about a project that no longer
# exists, which is how a disposed environment becomes a standing pager nuisance.
POL=$(gcloud alpha monitoring policies list --project="$PROJECT" --format='value(name)' 2>/dev/null \
      || curl -sS -H "Authorization: Bearer $(gcloud auth print-access-token 2>/dev/null)" \
         "https://monitoring.googleapis.com/v3/projects/${PROJECT}/alertPolicies" 2>/dev/null \
         | python3 -c 'import json,sys;d=json.load(sys.stdin);print("\n".join(p["name"] for p in d.get("alertPolicies",[])))' 2>/dev/null)
gone "WAL-43" "alert policies" "$(count "$POL")"

CH=$(curl -sS -H "Authorization: Bearer $(gcloud auth print-access-token 2>/dev/null)" \
     "https://monitoring.googleapis.com/v3/projects/${PROJECT}/notificationChannels" 2>/dev/null \
     | python3 -c 'import json,sys;d=json.load(sys.stdin);print("\n".join(c["name"] for c in d.get("notificationChannels",[])))' 2>/dev/null)
gone "WAL-43" "notification channels" "$(count "$CH")"

LM=$(gcloud logging metrics list --project="$PROJECT" --format='value(name)' 2>/dev/null | grep -E 'walrus' || true)
gone "WAL-43" "walrus log-based metrics" "$(count "$LM")"

# =========================================================================================
head_ "Deliberately retained — must still be here"
# =========================================================================================
# teardown.sh names these three in its closing output. Asserting they survived is not pedantry:
# the artifact bucket holds every cached upstream binary, and `gcs_force_destroy=true` is set
# during teardown precisely so the bucket *could* be emptied. A teardown that took it would print
# "Teardown complete" and look identical to a good one.
check_kept() {
  local tag="$1" what="$2" present="$3"
  if [ -n "$present" ]; then ok "$tag" "$what: retained as documented"
  else no "$tag" "$what: MISSING — teardown removed something it documents as kept"; fi
}

if [ -n "${TERRAFORM_STATE_BUCKET:-}" ]; then
  check_kept "WAL-93" "Terraform state bucket (gs://${TERRAFORM_STATE_BUCKET})" \
    "$(gcloud storage buckets describe "gs://${TERRAFORM_STATE_BUCKET}" --format='value(name)' 2>/dev/null)"
else
  warn "WAL-93" "TERRAFORM_STATE_BUCKET unset — source deploy.env to check the state bucket"
fi

if [ -n "${TF_VAR_gcs_bucket_name:-}" ]; then
  check_kept "WAL-93" "artifact bucket (gs://${TF_VAR_gcs_bucket_name})" \
    "$(gcloud storage buckets describe "gs://${TF_VAR_gcs_bucket_name}" --format='value(name)' 2>/dev/null)"
else
  warn "WAL-93" "TF_VAR_gcs_bucket_name unset — source deploy.env to check the artifact bucket"
fi

check_kept "WAL-93" "Artifact Registry 'walrus' repository" \
  "$(gcloud artifacts repositories describe walrus --location="$REGION" --project="$PROJECT" --format='value(name)' 2>/dev/null)"

# =========================================================================================
printf '\n-------------------------------------------------------------\n'
printf '%d passed, %d failed, %d warning(s)\n' "$PASS" "$FAIL" "$WARN"
if [ "$FAIL" -eq 0 ]; then
  printf 'Keep this output: it is WAL-93'"'"'s manual-test evidence and the run is not repeatable.\n'
fi
[ "$FAIL" -eq 0 ]
