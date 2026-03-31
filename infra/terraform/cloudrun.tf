resource "google_cloud_run_v2_service" "walrus" {
  name     = "walrus-api"
  location = var.region

  template {
    service_account = google_service_account.walrus_api.email

    timeout = "3600s"

    scaling {
      min_instance_count = var.cloud_run_min_instances
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = ["${var.project_id}:${var.region}:walrus-postgres"]
      }
    }

    containers {
      image = "${var.region}-docker.pkg.dev/${var.project_id}/walrus/walrus-api:${var.image_tag}"

      ports {
        container_port = 8080
      }

      env {
        name  = "NODE_ENV"
        value = "production"
      }
      env {
        name  = "DOWNLOAD_CONCURRENCY"
        value = "8"
      }
      env {
        name  = "STORAGE_BACKEND"
        value = "gcs"
      }
      env {
        name  = "GCS_BUCKET"
        value = var.gcs_bucket_name
      }
      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        failure_threshold = 10
        period_seconds    = 5
      }
    }
  }

  deletion_protection = false

  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }
}
