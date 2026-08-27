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

        # Pinned rather than inherited, because two workloads share this job and both scale
        # with DOWNLOAD_CONCURRENCY = 8.
        #
        # Memory: a download streams, so it is flat in artifact size; the resident cost is the
        # resumable-upload chunk buffer, GCS_UPLOAD_CHUNK_BYTES x DOWNLOAD_CONCURRENCY, both set
        # below — 32 MiB x 8 = 256 MiB. 2Gi leaves room for Node's heap and for that ceiling to
        # be raised without a re-plan. Raising either env var without re-reading this is the way
        # to OOM this job.
        #
        # CPU: downloads are IO-bound and would be content with less, but the archive
        # repackaging transform (WAL-57) is CPU-bound and holds decompress/deflate state per
        # artifact at ~10-30s of CPU each. Two vCPU is what keeps a bounded number of those
        # from contending on a single core — the sizing WAL-61 asks for, made once here rather
        # than by two tickets editing the same lines. WAL-61 still owns bounding transform
        # concurrency below DOWNLOAD_CONCURRENCY.
        resources {
          limits = {
            cpu    = "2"
            memory = "2Gi"
          }
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
          name  = "DOWNLOAD_CONCURRENCY"
          value = "8"
        }
        # 32 MiB, above the code default: this job pins the memory that pays for it, and larger
        # chunks mean fewer round trips across a 25.8 GB backfill.
        env {
          name  = "GCS_UPLOAD_CHUNK_BYTES"
          value = "33554432"
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
