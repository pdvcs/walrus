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
        name  = "GCP_PROJECT"
        value = var.project_id
      }
      env {
        name  = "GCP_REGION"
        value = var.region
      }
      env {
        name  = "VULN_BACKFILL_JOB"
        value = google_cloud_run_v2_job.vuln_backfill.name
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

resource "google_cloud_run_v2_job" "vuln_backfill" {
  name     = "walrus-vuln-backfill"
  location = var.region

  template {
    template {
      service_account = google_service_account.walrus_api.email
      timeout         = "86400s"
      max_retries     = 1

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = ["${var.project_id}:${var.region}:walrus-postgres"]
        }
      }

      containers {
        image   = "${var.region}-docker.pkg.dev/${var.project_id}/walrus/walrus-api:${var.image_tag}"
        command = ["node", "dist/commands/vuln-backfill-job.js"]
        args    = ["--job-id", "overridden-by-launcher"]
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
      }
    }
  }
}

# Package sync as a Job rather than an HTTP endpoint. The sync downloads artifacts that run
# to hundreds of MB, which no request deadline accommodates: Cloud Scheduler abandons a
# request after 30 minutes at most, and Cloud Run throttles CPU once a response is sent, so
# "respond early and keep working" is not safe either. See ADR-004 commitment 1.
resource "google_cloud_run_v2_job" "sync" {
  name     = "walrus-sync"
  location = var.region

  template {
    template {
      service_account = google_service_account.walrus_api.email
      timeout         = var.sync_job_timeout
      # No retries: the job already continues past a single package's failure, and a whole
      # re-run would re-resolve every package. The next scheduled run is the retry.
      max_retries = 0

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = ["${var.project_id}:${var.region}:walrus-postgres"]
        }
      }

      containers {
        image   = "${var.region}-docker.pkg.dev/${var.project_id}/walrus/walrus-api:${var.image_tag}"
        command = ["node", "dist/commands/sync-job.js"]
        env {
          name  = "STORAGE_BACKEND"
          value = "gcs"
        }
        env {
          name  = "GCS_BUCKET"
          value = var.gcs_bucket_name
        }
        env {
          name  = "DOWNLOAD_CONCURRENCY"
          value = "8"
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
      }
    }
  }
}
