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
