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

  # No `notification_rate_limit` here, unlike the log-based policies: the API rejects it with
  # "only log-based alert policies may specify a notification rate limit", and this one is a
  # metric threshold. Re-throttling is unnecessary anyway — the condition already aggregates over
  # a four-hour window, so it cannot fire per-event.
  alert_strategy {
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

# ---------------------------------------------------------------------------------------------
# WAL-119 — tier 2, charted.
#
# The five policies above are tier 1: they send email, and they are deliberately narrow, because
# `vuln_sync_degraded` is right that paging for a transient failure teaches people to ignore the
# channel. Tier 2 is the surface you *look at* rather than one that interrupts you: Cloud Error
# Reporting, which has grouped every stack-carrying error in this project since the first
# deployment at zero configuration, plus the dashboard below for the counts and trends Error
# Reporting does not chart.
#
# Nothing here notifies. That is the point of it.
# ---------------------------------------------------------------------------------------------

# Cloud Scheduler publishes **no** metric to Cloud Monitoring — verified against this project,
# where `cloudscheduler.googleapis.com/*` returns nothing at all while the `cloud_scheduler_job`
# monitored-resource type is perfectly well known. So a scheduler failure is chartable only from
# its log, the same way a vuln sync failure is.
#
# The filter is deliberately identical to `scheduler_job_failure`'s above, including its
# resource-type-not-job-name breadth: a seventh scheduler job is counted the moment it exists.
# The policy is left as a log-match policy rather than re-pointed at this metric — it should
# alert on the event, not on a threshold over an alignment window.
resource "google_logging_metric" "scheduler_job_failed" {
  name   = "walrus/scheduler_job_failed"
  filter = <<-EOT
    resource.type="cloud_scheduler_job"
    AND severity>=ERROR
  EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
    labels {
      key         = "job"
      value_type  = "STRING"
      description = "Cloud Scheduler job whose invocation failed"
    }
  }

  # Which job failed is the whole question — one chart line per job rather than a single total,
  # for the same reason vuln_sync_failed extracts its source.
  label_extractors = {
    "job" = "EXTRACT(resource.labels.job_id)"
  }
}

# The project's first dashboard, and it is Terraform like the policies are. A console-built
# dashboard is invisible to review, absent from a fresh project, and silently divergent from the
# moment someone drags a widget — which is the drift WAL-96 spent a ticket eliminating on the
# service. Do not hand-edit this in the console.
#
# Metric types below were each verified to exist in this project with the labels used here,
# rather than recalled: run.googleapis.com/request_count (response_code_class),
# run.googleapis.com/job/completed_execution_count (result), and the two log-based metrics. A
# chart built on a metric type that does not exist renders empty and looks like good news.
resource "google_monitoring_dashboard" "walrus" {
  dashboard_json = jsonencode({
    displayName = "Walrus operations"
    gridLayout = {
      columns = "2"
      widgets = [
        {
          # Per source, not a total: the alert next door groups by source for the same reason,
          # and "nvd is failing" and "everything is failing" want different responses.
          title = "Vulnerability sync failures by source"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.vuln_sync_failed.name}\" resource.type=\"cloud_run_revision\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_SUM"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.source"]
                  }
                }
              }
              plotType   = "STACKED_BAR"
              targetAxis = "Y1"
            }]
            yAxis = { label = "failures", scale = "LINEAR" }
          }
        },
        {
          title = "Cloud Scheduler invocation failures by job"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.scheduler_job_failed.name}\" resource.type=\"cloud_scheduler_job\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_SUM"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.job"]
                  }
                }
              }
              plotType   = "STACKED_BAR"
              targetAxis = "Y1"
            }]
            yAxis = { label = "failed attempts", scale = "LINEAR" }
          }
        },
        {
          # By class rather than by code: the question this answers is "is walrus serving", and a
          # 5xx rate is that. A specific status belongs in Logs Explorer.
          title = "walrus-api requests by response class"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"run.googleapis.com/request_count\" resource.type=\"cloud_run_revision\" resource.label.service_name=\"${google_cloud_run_v2_service.walrus.name}\""
                  aggregation = {
                    alignmentPeriod    = "300s"
                    perSeriesAligner   = "ALIGN_SUM"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["metric.label.response_code_class"]
                  }
                }
              }
              plotType   = "STACKED_BAR"
              targetAxis = "Y1"
            }]
            yAxis = { label = "requests", scale = "LINEAR" }
          }
        },
        {
          # Both Jobs on one chart, split by job and result. A sync job that silently stops
          # succeeding looks identical to one nobody triggered unless the result is on the axis.
          title = "Cloud Run Job executions by result"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"run.googleapis.com/job/completed_execution_count\" resource.type=\"cloud_run_job\""
                  aggregation = {
                    alignmentPeriod    = "3600s"
                    perSeriesAligner   = "ALIGN_SUM"
                    crossSeriesReducer = "REDUCE_SUM"
                    groupByFields      = ["resource.label.job_name", "metric.label.result"]
                  }
                }
              }
              plotType   = "STACKED_BAR"
              targetAxis = "Y1"
            }]
            yAxis = { label = "executions", scale = "LINEAR" }
          }
        },
      ]
    }
  })
}
