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

# walrus-api: Secret Accessor for DATABASE_URL
resource "google_secret_manager_secret_iam_member" "walrus_api_secret" {
  secret_id = google_secret_manager_secret.database_url.secret_id
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

# Public API access
resource "google_cloud_run_v2_service_iam_member" "walrus_public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.walrus.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
