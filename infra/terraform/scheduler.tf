resource "google_cloud_scheduler_job" "sync" {
  name      = "walrus-sync"
  region    = var.region
  schedule  = var.sync_schedule
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.walrus.uri}/internal/sync"

    oidc_token {
      service_account_email = google_service_account.walrus_scheduler.email
      audience              = google_cloud_run_v2_service.walrus.uri
    }
  }
}
