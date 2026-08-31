resource "google_service_account" "walrus_api" {
  account_id   = "walrus-api"
  display_name = "Walrus API Service Account"
}

resource "google_service_account" "walrus_scheduler" {
  account_id   = "walrus-scheduler"
  display_name = "Walrus Scheduler Service Account"
}

# walrus-api: GCS Object Admin on artifact bucket
resource "google_storage_bucket_iam_member" "walrus_api_gcs" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.walrus_api.email}"
}

# walrus-api: Cloud SQL Client (for Auth Proxy)
resource "google_project_iam_member" "walrus_api_cloudsql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.walrus_api.email}"
}

# walrus-api launches the dedicated long-running vulnerability backfill job, passing the database
# job id through `overrides.containerOverrides`. That needs `run.jobs.runWithOverrides`, which
# `roles/run.invoker` does **not** grant — invoker covers a plain `:run` only. The autonomous
# sweep therefore failed every launch with
# `Permission 'run.jobs.runWithOverrides' denied` until 2026-08-30 (WAL-99), silently, because
# per-package launch failures are logged and swallowed.
#
# A custom role rather than `roles/run.developer`, which would also carry create/update/delete on
# every Cloud Run resource in the project. This account needs to start one job and nothing else.
resource "google_project_iam_custom_role" "job_runner" {
  role_id     = "walrusJobRunner"
  title       = "Walrus Cloud Run Job Runner"
  description = "Start a Cloud Run Job, with container overrides. Least-privilege alternative to roles/run.developer."
  permissions = [
    "run.jobs.run",
    "run.jobs.runWithOverrides",
  ]
}

resource "google_cloud_run_v2_job_iam_member" "walrus_api_backfill_runner" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.vuln_backfill.name
  role     = google_project_iam_custom_role.job_runner.id
  member   = "serviceAccount:${google_service_account.walrus_api.email}"
}

# walrus-api: Secret Accessor for DATABASE_URL
resource "google_secret_manager_secret_iam_member" "walrus_api_secret" {
  secret_id = google_secret_manager_secret.database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.walrus_api.email}"
}

resource "google_secret_manager_secret_iam_member" "walrus_api_session_secret" {
  secret_id = google_secret_manager_secret.session_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.walrus_api.email}"
}

resource "google_secret_manager_secret_iam_member" "walrus_api_previous_session_secret" {
  secret_id = google_secret_manager_secret.session_secret_previous.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.walrus_api.email}"
}

resource "google_secret_manager_secret_iam_member" "walrus_api_admin_password" {
  secret_id = google_secret_manager_secret.admin_password.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.walrus_api.email}"
}

# walrus-scheduler: Cloud Run Invoker
resource "google_cloud_run_v2_service_iam_member" "walrus_scheduler_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.walrus.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.walrus_scheduler.email}"
}

# walrus-scheduler: run the sync Job. Distinct from the service invoker binding above —
# executing a Cloud Run Job is a separate permission from invoking a Cloud Run service.
resource "google_cloud_run_v2_job_iam_member" "walrus_scheduler_job_runner" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.sync.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.walrus_scheduler.email}"
}

# Public API access
resource "google_cloud_run_v2_service_iam_member" "walrus_public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.walrus.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# walrus-api: Secret Accessor for the upstream NVD API key (WAL-92). One binding covers all three
# workloads that read it — the service and both Cloud Run Jobs run as this account. Granted
# whether or not a version exists yet, so populating the key later needs no IAM change.
resource "google_secret_manager_secret_iam_member" "walrus_api_nvd_api_key" {
  secret_id = google_secret_manager_secret.nvd_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.walrus_api.email}"
}

# walrus-api: Secret Accessor for the upstream GitHub token (WAL-103). All three workloads run as
# this account, but only walrus-sync mounts the token — see cloudrun.tf. Granted whether or not a
# version exists yet, so supplying the token later needs no IAM change.
resource "google_secret_manager_secret_iam_member" "walrus_api_github_token" {
  secret_id = google_secret_manager_secret.github_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.walrus_api.email}"
}
