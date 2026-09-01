# Executes the walrus-sync Cloud Run Job rather than POSTing /internal/sync. The request
# only has to start the execution, so the attempt deadline no longer bounds how long a sync
# may take, and the work runs in its own container instead of outliving a response.
# Authenticates with an OAuth token because the target is a Google API, not our service.
resource "google_cloud_scheduler_job" "sync" {
  name             = "walrus-sync"
  region           = var.region
  schedule         = var.sync_schedule
  time_zone        = "UTC"
  attempt_deadline = "320s"

  retry_config {
    retry_count          = 1
    min_backoff_duration = "60s"
  }

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.sync.name}:run"

    oauth_token {
      service_account_email = google_service_account.walrus_scheduler.email
      scope                 = "https://www.googleapis.com/auth/cloud-platform"
    }
  }
}

# ── Vulnerability ingestion ───────────────────────────────────────────────────
#
# One job per source rather than a single /vuln-sync/all call: the sources want
# genuinely different cadences (NVD changes constantly, KEV is daily, OSV is a
# weekly cross-check), which `all` cannot express, and a per-source job fails and
# alerts in isolation instead of dragging the others into one red run.
#
# `cvss` IS scheduled, by PO decision (2026-08-26): in this enterprise context safety
# outweighs availability. Enrichment can newly satisfy the >= 9.0 gate and turn a
# version that serves today into a 403 — which is the intended behaviour, not a
# hazard to be gated behind a human. A predictable "we err on the side of denial
# once a CVE scores above the limit" is defensible to compliance; leaving known
# CVEs unscored because nobody ran the repair pass is not.
#
# It stays excluded from `/vuln-sync/all` in the orchestrator: that keeps routine
# ingestion fast, and this job triggers the source directly. The admin preview
# (/admin/v1/vulns → CVSS enrichment) remains the tool for ad-hoc checks and for
# seeing which versions a run would block.
#
# `body` is null for every source but cvss: it is the only one with a bounded-run option to
# express (WAL-48). A null body means Cloud Scheduler POSTs nothing, which is what the other
# three routes expect.
locals {
  vuln_sync_jobs = {
    nvd = {
      body     = null
      schedule = var.vuln_sync_nvd_schedule
      # Cloud Scheduler's default attempt deadline is 180s, well under an
      # incremental NVD walk. 1800s is the maximum it allows; the Cloud Run
      # service itself permits 3600s, so the scheduler is the binding limit.
      deadline = "1800s"
      # One retry, and the reason is narrower than it looks (WAL-106).
      #
      # This was 0, on the argument that the NVD cursor only advances on success, so the next
      # scheduled run repeats the same window anyway and a retry would mostly re-hit the advisory
      # lock and log 409s. That holds for a request that *arrived* and met a running sync. It does
      # not hold for a Cloud Run 429 — `no available instance`, WAL-105 — where the request never
      # reached walrus at all: no lock was taken, no cursor was read, and there is no work to
      # duplicate. A retry is the correct response to that in a way it is not to a 409.
      #
      # The retry can still land on a genuine 409 if a slow walk is in flight at +600s. That costs
      # one alert email, which is what a lost window costs anyway, so the trade only ever improves
      # on the previous behaviour. `min_backoff_duration` below is shared across these jobs and is
      # deliberately not shortened: cvss depends on that gap to clear the nvd lock safely.
      retries = 1
    }
    kev = {
      body     = null
      schedule = var.vuln_sync_kev_schedule
      deadline = "600s"
      retries  = 1
    }
    osv = {
      body     = null
      schedule = var.vuln_sync_osv_schedule
      deadline = "1800s"
      # Weekly, so a lost run leaves the cross-check stale for seven days.
      retries = 2
    }
    cvss = {
      # WAL-48: bound the scheduled run so it finishes inside the deadline below. Without it the
      # job walks the entire un-scored backlog and is cut off mid-walk on a large one.
      body     = jsonencode({ limit = var.vuln_sync_cvss_limit })
      schedule = var.vuln_sync_cvss_schedule
      deadline = "1800s"
      # cvss takes the *nvd* lock, so a run overlapping incremental ingestion gets
      # 409 already_running. One backed-off retry clears that without leaving the
      # gate unenforced for a day; the walk is resumable, so a deadline-exceeded
      # run simply continues from the remaining candidates next time.
      retries = 1
    }
  }
}

resource "google_cloud_scheduler_job" "vuln_sync" {
  for_each = local.vuln_sync_jobs

  name             = "walrus-vuln-sync-${each.key}"
  region           = var.region
  schedule         = each.value.schedule
  time_zone        = "UTC"
  attempt_deadline = each.value.deadline

  retry_config {
    retry_count = each.value.retries
    # Long enough that a retry lands after a contended lock has been released
    # rather than immediately bouncing off it again.
    min_backoff_duration = "600s"
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.walrus.uri}/internal/vuln-sync/${each.key}"
    # Cloud Scheduler sends the body verbatim, so the route needs the content type to parse it.
    headers = each.value.body == null ? {} : { "Content-Type" = "application/json" }
    body    = each.value.body == null ? null : base64encode(each.value.body)

    oidc_token {
      service_account_email = google_service_account.walrus_scheduler.email
      audience              = var.internal_oidc_audience
    }
  }
}

# Autonomous per-package CVE backfill sweep (WAL-37, ADR-003 commitment 2).
#
# Incremental NVD sync is cursor-based, so it is structurally blind to a newly tracked
# package's *history*. Without this sweep that gap closes only when a human remembers to
# run a targeted backfill — and nothing warns them, because the old hint fired only when
# cve_affects was globally empty. Daily is ample: it is a gap-closer, not ingestion.
resource "google_cloud_scheduler_job" "vuln_backfill_auto" {
  name             = "walrus-vuln-backfill-auto"
  region           = var.region
  schedule         = var.vuln_backfill_auto_schedule
  time_zone        = "UTC"
  attempt_deadline = "320s"

  retry_config {
    retry_count          = 1
    min_backoff_duration = "300s"
  }

  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.walrus.uri}/internal/vuln-backfill/auto"

    oidc_token {
      service_account_email = google_service_account.walrus_scheduler.email
      audience              = var.internal_oidc_audience
    }
  }
}
