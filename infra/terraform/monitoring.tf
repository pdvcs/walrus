# Minimal operational alerting: one immediate signal for a failed Cloud Run process/job and one
# for a package falling permanently out of autonomous CVE backfill. Keep alert ownership outside
# source through alert_notification_email; deploy.sh derives a sole project owner for small dev
# projects and requires an explicit address for shared environments.
resource "google_monitoring_notification_channel" "walrus_email" {
  display_name = "Walrus operational email"
  type         = "email"

  labels = {
    email_address = var.alert_notification_email
  }
}

resource "google_monitoring_alert_policy" "cloud_run_errors" {
  display_name = "Walrus Cloud Run error"
  combiner     = "OR"
  severity     = "ERROR"

  conditions {
    display_name = "Walrus service or Job emitted an error"

    condition_matched_log {
      filter = <<-EOT
        (resource.type="cloud_run_revision" OR resource.type="cloud_run_job")
        AND severity>=ERROR
        AND (resource.labels.service_name="walrus-api" OR resource.labels.job_name="walrus-sync" OR resource.labels.job_name="walrus-vuln-backfill")
      EOT
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = "A Walrus Cloud Run service or Job emitted an error. Inspect Cloud Run logs and the `/app/status` response; retry or investigate the affected sync before data becomes stale."
  }

  notification_channels = [google_monitoring_notification_channel.walrus_email.name]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }
}

resource "google_monitoring_alert_policy" "backfill_retry_exhausted" {
  display_name = "Walrus automatic CVE backfill exhausted"
  severity     = "WARNING"
  combiner     = "OR"

  conditions {
    display_name = "A package exhausted automatic CVE backfill retries"

    condition_matched_log {
      filter = "resource.type=\"cloud_run_revision\" AND resource.labels.service_name=\"walrus-api\" AND jsonPayload.msg=\"Package exhausted automatic CVE backfill retries\""
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = "A package will no longer receive automatic CVE history backfills. Inspect `/app/status` and the backfill error, then run a targeted package backfill after correcting the cause."
  }

  notification_channels = [google_monitoring_notification_channel.walrus_email.name]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "86400s"
  }
}

# ---------------------------------------------------------------------------------------------
# WAL-43 AC2 — Cloud Scheduler job failure.
#
# The Cloud Run policy above cannot cover this. A scheduler invocation that never reaches the
# service — a wrong URL, a revoked OIDC binding, a service refusing the principal — produces no
# Cloud Run log at all; it is recorded against the scheduler job. That is precisely the failure
# WAL-86's auth work can regress into, and it would otherwise be silent.
#
# Filtered on the resource TYPE rather than an enumerated list of job names, as the AC requires:
# a seventh scheduler job added to scheduler.tf is covered the moment it exists, with no edit
# here. An enumerated list would drift silently, and its drift is invisible until the alert that
# was never written fails to fire.
# ---------------------------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "scheduler_job_failure" {
  display_name = "Walrus scheduler job failed"
  combiner     = "OR"
  severity     = "ERROR"

  conditions {
    display_name = "A Cloud Scheduler job reported failure"

    condition_matched_log {
      filter = <<-EOT
        resource.type="cloud_scheduler_job"
        AND severity>=ERROR
      EOT
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      A Cloud Scheduler job failed to invoke its target. The workload itself may be healthy — this
      fires when the *invocation* fails, which the Cloud Run error alert cannot see.

      Check, in order: the job's `lastAttemptTime` and status in `gcloud scheduler jobs list`; the
      target URL against the current Cloud Run URL; and the OIDC service account binding, since a
      revoked `run.invoker` presents as a failed attempt rather than as a deploy error.
    EOT
  }

  notification_channels = [google_monitoring_notification_channel.walrus_email.name]

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
    auto_close = "1800s"
  }
}

# ---------------------------------------------------------------------------------------------
# WAL-43 AC3 — a degradation that persists, not one that blinks.
#
# `/app/status` reports a degradation as soon as one sync attempt fails, and that is correct for
# a dashboard and wrong for an alert: on 2026-08-31 the NVD sync failed at 14:20:33Z on a 30s
# upstream timeout and the next scheduled tick recovered on its own. Paging a human for that
# teaches them to ignore the channel, which costs more than the alert is worth.
#
# So the signal is *two* failures rather than a duration on a gauge: each vulnerability source
# runs on a fixed cadence, so a second consecutive failure means the retry the first one was
# entitled to has already happened and also failed. That is the same distinction
# verify-deployment.sh draws between a transient upstream failure and real staleness.
# ---------------------------------------------------------------------------------------------
resource "google_logging_metric" "vuln_sync_failed" {
  name   = "walrus/vuln_sync_failed"
  filter = <<-EOT
    resource.type="cloud_run_revision"
    AND resource.labels.service_name="walrus-api"
    AND jsonPayload.msg="vuln sync failed"
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "source"
      value_type  = "STRING"
      description = "Vulnerability source that failed: nvd, kev, osv or cvss"
    }
  }

  # Keeping the source as a label rather than one metric per source means a source added later
  # is counted without a Terraform change, and the alert can still say which one is failing.
  label_extractors = {
    "source" = "EXTRACT(jsonPayload.source)"
  }
}

resource "google_monitoring_alert_policy" "vuln_sync_degraded" {
  display_name = "Walrus vulnerability sync degraded"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "A vulnerability source failed more than once"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vuln_sync_failed.name}\" AND resource.type=\"cloud_run_revision\""
      comparison      = "COMPARISON_GT"
      threshold_value = 1
      # Four hours spans two ticks of the fastest source (nvd, every two hours), so a second
      # failure inside the window is a source that has already had its retry.
      duration = "0s"

      aggregations {
        alignment_period     = "14400s"
        per_series_aligner   = "ALIGN_SUM"
        cross_series_reducer = "REDUCE_SUM"
        group_by_fields      = ["metric.label.source"]
      }

      trigger {
        count = 1
      }
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      A vulnerability source has failed more than once in four hours, so its data is going stale
      rather than having a bad minute. A single failure deliberately does not alert.

      Check `/app/status` for `vuln_sync_status.<source>.last_success` to see how far behind the
      source is, then the Cloud Run logs for the failure itself. Upstream rate limiting and
      upstream outage look different in the log and want different responses — the former resets
      on its own, the latter does not.
    EOT
  }

  notification_channels = [google_monitoring_notification_channel.walrus_email.name]

  alert_strategy {
    notification_rate_limit {
      period = "3600s"
    }
    auto_close = "86400s"
  }
}

# ---------------------------------------------------------------------------------------------
# WAL-43 AC5 — versions newly became undownloadable.
#
# Informational, not pager: this is walrus working correctly. A CVE arrived and the gate did its
# job. But someone has to know, because a developer's build will start failing on a version that
# worked yesterday and the reason lives here rather than in their pipeline.
#
# Severity and a slow rate limit carry that intent — the alert should never wake anyone, and AC5
# asks for exactly this routing distinction.
# ---------------------------------------------------------------------------------------------
resource "google_monitoring_alert_policy" "versions_newly_blocked" {
  display_name = "Walrus blocked a version (informational)"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "A sync newly blocked one or more versions"

    condition_matched_log {
      filter = <<-EOT
        resource.type="cloud_run_revision"
        AND jsonPayload.msg="Recorded version availability transitions"
        AND jsonPayload.blocked>0
      EOT
    }
  }

  documentation {
    mime_type = "text/markdown"
    content   = <<-EOT
      One or more versions became undownloadable because a newly ingested CVE meets the gate.
      **This is walrus working as designed** — no action is required to fix walrus.

      It is sent so the block is not discovered as a mystery build failure. Check
      `/api/v1/packages/<name>/vulns` for what was blocked and why, and if a version must be
      served regardless, that is a CVE suppression decision with an audit trail, not a config
      change.
    EOT
  }

  notification_channels = [google_monitoring_notification_channel.walrus_email.name]

  alert_strategy {
    notification_rate_limit {
      # Informational: a large sync can block many versions at once, and one message about that
      # is enough.
      period = "3600s"
    }
    auto_close = "86400s"
  }
}
