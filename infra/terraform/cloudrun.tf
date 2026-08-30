# Derived from the pinned max_connections rather than declared alongside it, so the two cannot
# drift. See the budget block in variables.tf.
locals {
  db_usable_connections = var.db_max_connections - var.db_reserved_connections
}

resource "google_cloud_run_v2_service" "walrus" {
  name     = "walrus-api"
  location = var.region


  # The connection_name reference in the volume waits for the instance; these wait for the things
  # container actually needs to exist at boot. A user or database creation still in flight leaves
  # the instance unable to issue an ephemeral cert, which the client reports as a 409 invalidState.
  depends_on = [
    google_sql_database.walrus,
    google_sql_user.walrus,
  ]

  template {
    service_account = google_service_account.walrus_api.email

    timeout = "3600s"

    # Bounded by the Cloud SQL connection budget, not by CPU headroom -- the database is the
    # constraint. The four variables and the invariant they satisfy are documented together in
    # variables.tf, and enforced by the precondition at the bottom of this resource.
    scaling {
      min_instance_count = var.cloud_run_min_instances
      max_instance_count = var.cloud_run_max_instances
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        # A reference, not the equivalent literal string: the literal left Terraform's graph with
        # no edge to the database at all, so this service could be created while the instance was
        # still mid-operation. The container fails fast on an unreachable database, so that raced
        # apply surfaced as "failed the configured startup probe checks" — see the depends_on
        # below and WAL-94.
        instances = [google_sql_database_instance.walrus.connection_name]
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
      # One, not the sync job's two (WAL-61 AC2). This service runs on-demand syncs of the
      # same packages the job does, and a transform holds its measured link-cache window in
      # memory (~475 MiB for gitwindows' arm64 tree) — which does not fit the 512 MiB
      # Cloud Run default this service otherwise inherits, hence the resources pin below.
      # One transform at a time keeps the worst case inside 1Gi with room for Node.
      env {
        name  = "TRANSFORM_CONCURRENCY"
        value = "1"
      }
      # Multiplied by the instance ceiling above. Downloads stream from GCS and hold no
      # connection across the transfer, so this bounds concurrent metadata work, not concurrent
      # downloads -- DOWNLOAD_CONCURRENCY may safely exceed it.
      env {
        name  = "DB_POOL_MAX"
        value = tostring(var.service_db_pool_max)
      }
      # V8's old-space ceiling, set rather than inherited (WAL-95 AC4). Node defaults to roughly
      # half the container, which sounds conservative and is not: the heap is only one claimant on
      # the 1Gi below, and Buffers live *outside* it. Both can reach their maximum at once, and the
      # container is then OOM-killed with no stack.
      #
      #   1024 MiB container
      #   - 475  link cache, one transform (TRANSFORM_CONCURRENCY = 1)
      #   -  64  upload chunks, 8 MiB x DOWNLOAD_CONCURRENCY 8 (the code default; unpinned here)
      #   -  80  Node itself: code, stacks, young generation, native allocations
      #   = 405 available to old space -> 384, rounded down for headroom
      #
      # A heap-limit fatal is also a better failure than an OOM-kill: it names the limit and prints
      # a stack, which is exactly how WAL-95 was diagnosed.
      env {
        name  = "NODE_OPTIONS"
        value = "--max-old-space-size=384"
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
        name  = "WALRUS_INTERNAL_AUDIENCE"
        value = var.internal_oidc_audience
      }
      env {
        name  = "WALRUS_INTERNAL_SERVICE_ACCOUNT"
        value = google_service_account.walrus_scheduler.email
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
      env {
        name = "WALRUS_SESSION_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_secret.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "WALRUS_SESSION_SECRET_PREVIOUS"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.session_secret_previous.secret_id
            version = "latest"
          }
        }
      }
      env {
        name = "WALRUS_ADMIN_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.admin_password.secret_id
            version = "latest"
          }
        }
      }
      # Upstream NVD credential (WAL-92). This service runs the scheduled /internal/vuln-sync/nvd
      # and /internal/vuln-sync/cvss walks in-request, so it is the fleet's steady-state NVD
      # caller. Mounted only when deploy.sh saw an NVD_API_KEY and populated a version: Cloud Run
      # will not start a revision whose referenced secret is empty, and keyless is a supported
      # mode (5 req/30s instead of 50), so an unsupplied key must degrade, not break the deploy.
      dynamic "env" {
        for_each = var.nvd_api_key_configured ? [1] : []
        content {
          name = "NVD_API_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.nvd_api_key.secret_id
              version = "latest"
            }
          }
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      # Pinned for the on-demand sync path this service can execute (WAL-61): a transform
      # holds its link-cache window in RAM (~475 MiB for gitwindows arm64), which does not
      # fit the 512 MiB default. 1Gi covers one transform (TRANSFORM_CONCURRENCY = 1 above)
      # plus Node and the 8 MiB x 8 upload chunks. The scheduled syncs with their heavier
      # workload run on the sync job, which pins 2Gi for them.
      resources {
        limits = {
          cpu    = "1"
          memory = "1Gi"
        }
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
    # `image`: deploy.sh Phase 7 rolls new images out with `gcloud run services update`, because a
    # Terraform-owned image would make every deploy a Terraform run.
    #
    # The rest are fields Terraform does not declare but the API or gcloud returns anyway, each of
    # which made `terraform plan` permanently dirty after a deploy (WAL-96). That is corrosive
    # rather than harmful: a plan that always shows a diff on the most important resource in the
    # project trains reviewers to skim past it, which is exactly how the next real drift gets
    # missed.
    #   client / client_version    - stamped by `gcloud run services update`; re-added every deploy.
    #   scaling                    - the *service-level* block, distinct from template.scaling
    #                                below. The API returns it populated with zeros, so Terraform
    #                                proposes removing zeros, which is a server-side no-op: the
    #                                diff cannot be applied away, only ignored.
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
      scaling,
    ]

    # The connection budget, enforced rather than documented. `x 2` is the two Cloud Run Jobs
    # below, each of which runs one execution at a time; add a third job and this must change.
    # A `check` block would only warn -- this fails the plan, which is the point: the failure
    # mode it guards against is a scale-up that exhausts Postgres and takes the service down
    # instead of relieving it.
    precondition {
      condition     = ((var.service_db_pool_max * var.cloud_run_max_instances) + (var.job_db_pool_max * 2)) <= local.db_usable_connections
      error_message = "Cloud SQL connection budget exceeded: service_db_pool_max x cloud_run_max_instances + job_db_pool_max x 2 must be <= db_max_connections - db_reserved_connections. Raise the Cloud SQL tier and db_max_connections together, or lower the pools/ceiling."
    }
  }
}

resource "google_cloud_run_v2_job" "vuln_backfill" {
  name     = "walrus-vuln-backfill"
  location = var.region

  # The connection_name reference in the volume waits for the instance; these wait for the things
  # container actually needs to exist at boot. A user or database creation still in flight leaves
  # the instance unable to issue an ephemeral cert, which the client reports as a 409 invalidState.
  depends_on = [
    google_sql_database.walrus,
    google_sql_user.walrus,
  ]


  # See var.job_deletion_protection: the provider default is true, and teardown.sh
  # cannot destroy this Job until it is lowered.
  deletion_protection = var.job_deletion_protection

  template {
    template {
      service_account = google_service_account.walrus_api.email
      timeout         = "86400s"
      max_retries     = 1

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          # A reference, not the literal — see the service above and WAL-94.
          instances = [google_sql_database_instance.walrus.connection_name]
        }
      }

      containers {
        image   = "${var.region}-docker.pkg.dev/${var.project_id}/walrus/walrus-api:${var.image_tag}"
        command = ["node", "dist/commands/vuln-backfill-job.js"]
        args    = ["--job-id", "overridden-by-launcher"]

        # Pinned rather than left at Cloud Run's defaults (WAL-97 AC4). This was the only workload
        # with no resources block at all, which meant nothing stated what it was entitled to --
        # and until WAL-97 it accumulated a whole CPE pair's CVEs, so its appetite was unbounded
        # on a container size nobody had chosen.
        #
        # Memory: it now streams a page at a time (2,000 CVEs), so the resident set is one parsed
        # page plus Node, not the pair's whole result. A CVE record with configurations and
        # references runs to a few KB and JSON parsing inflates that several times over, so a page
        # is tens of MB; 1Gi is generous against that and leaves room for a page of unusual size
        # without a re-plan. Unlike the sync job there is no Buffer-heavy path here -- no
        # transforms, no upload chunks -- so nearly all of this is available to the JS heap.
        #
        # CPU: the work is IO-bound and rate-limited by NVD (45 req/30s with a key, 4 without), so
        # this is bounded by the upstream budget rather than by cores. One vCPU is ample, and jobs
        # bill only while executing.
        resources {
          limits = {
            cpu    = "1"
            memory = "1Gi"
          }
        }
        # One execution at a time; counts once in the budget. See variables.tf.
        env {
          name  = "DB_POOL_MAX"
          value = tostring(var.job_db_pool_max)
        }
        # This job has no Buffer-heavy path -- no transforms, no upload chunks -- so nearly the
        # whole container is available to the heap: 1024 MiB less ~80 for Node itself, less slack
        # for an unusually large NVD page, -> 768. Since WAL-97 it streams a page at a time, so
        # this bounds one page of parsed CVEs rather than a whole CPE pair's results.
        env {
          name  = "NODE_OPTIONS"
          value = "--max-old-space-size=768"
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
        # Upstream NVD credential (WAL-92). This job pages NVD per CPE pair across the whole
        # history, so it is the workload the key matters most to — keyless it is the multi-hour
        # run build-release.md warns about. Mounted only when a version exists: Cloud Run will
        # not start a revision whose referenced secret is empty.
        dynamic "env" {
          for_each = var.nvd_api_key_configured ? [1] : []
          content {
            name = "NVD_API_KEY"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.nvd_api_key.secret_id
                version = "latest"
              }
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

  # The connection_name reference in the volume waits for the instance; these wait for the things
  # container actually needs to exist at boot. A user or database creation still in flight leaves
  # the instance unable to issue an ephemeral cert, which the client reports as a 409 invalidState.
  depends_on = [
    google_sql_database.walrus,
    google_sql_user.walrus,
  ]


  # See var.job_deletion_protection: the provider default is true, and teardown.sh
  # cannot destroy this Job until it is lowered.
  deletion_protection = var.job_deletion_protection

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
          # A reference, not the literal — see the service above and WAL-94.
          instances = [google_sql_database_instance.walrus.connection_name]
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
        # Bounded independently of DOWNLOAD_CONCURRENCY (WAL-61 AC2): downloads are IO-bound
        # and eight of them are fine; a transform is CPU-bound and holds live bzip2/deflate
        # state plus the measured hardlink link-cache window (~475 MiB for gitwindows' arm64
        # tree) per artifact. Two transforms saturate the 2 pinned vCPUs; the worst-case
        # resident set is 2 x 512 MiB of link cache + 256 MiB of upload chunks + Node — inside
        # the 2Gi above, with little to spare. Do not raise DOWNLOAD_CONCURRENCY to compensate
        # for a slow transform: the two limits govern different resources.
        env {
          name  = "TRANSFORM_CONCURRENCY"
          value = "2"
        }
        # 32 MiB, above the code default: this job pins the memory that pays for it, and larger
        # chunks mean fewer round trips across a 25.8 GB backfill.
        env {
          name  = "GCS_UPLOAD_CHUNK_BYTES"
          value = "33554432"
        }
        # Old-space ceiling, from the same budget the resources block above reasons about:
        #
        #   2048 MiB container
        #   - 1024  link cache, 2 x 512 (TRANSFORM_CONCURRENCY = 2)
        #   -  256  upload chunks, 32 MiB x DOWNLOAD_CONCURRENCY 8
        #   -   80  Node itself
        #   =  688 available to old space -> 640, rounded down for headroom
        #
        # Raising TRANSFORM_CONCURRENCY or GCS_UPLOAD_CHUNK_BYTES eats this directly.
        env {
          name  = "NODE_OPTIONS"
          value = "--max-old-space-size=640"
        }
        # One execution at a time, so this counts once in the budget rather than per instance.
        env {
          name  = "DB_POOL_MAX"
          value = tostring(var.job_db_pool_max)
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
        # Upstream NVD credential (WAL-92 AC2). This job does not reach NVD today — package sync
        # never enters the vuln path — but the ticket wires all three workloads that run as
        # walrus-api so no future caller here inherits the keyless 5 req/30s limit silently.
        # Mounted only when a version exists: Cloud Run will not start a revision otherwise.
        dynamic "env" {
          for_each = var.nvd_api_key_configured ? [1] : []
          content {
            name = "NVD_API_KEY"
            value_source {
              secret_key_ref {
                secret  = google_secret_manager_secret.nvd_api_key.secret_id
                version = "latest"
              }
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
