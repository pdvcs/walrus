variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "gcs_bucket_name" {
  description = "Name of the GCS bucket for cached binary artifacts"
  type        = string
}

variable "cloud_sql_db_password" {
  description = "Password for the Cloud SQL walrus user"
  type        = string
  sensitive   = true
}

variable "cloud_sql_tier" {
  description = "Cloud SQL machine type"
  type        = string
  default     = "db-f1-micro"
}

variable "image_tag" {
  description = "Docker image tag (git SHA) — set by deploy.sh"
  type        = string
}

variable "cloud_run_min_instances" {
  description = "Minimum number of Cloud Run instances (use 1 for always-on)"
  type        = number
  default     = 1
}

variable "internal_oidc_audience" {
  description = "Exact OIDC audience shared by Cloud Scheduler and the /internal verifier"
  type        = string
  default     = "walrus-internal"
}

variable "sync_schedule" {
  description = "Cron schedule for Cloud Scheduler sync job (UTC)"
  type        = string
  default     = "0 */6 * * *"
}

# Vuln ingestion cadences follow engineering/docs/build-release.md §3. Minutes are
# offset from the package sync (minute 0) and from each other so the sources do not
# contend for the same instance -- nvd and cvss also share one advisory lock.
variable "vuln_sync_nvd_schedule" {
  description = "Cron schedule for the incremental NVD vuln sync (UTC)"
  type        = string
  default     = "20 */2 * * *"
}

variable "vuln_sync_kev_schedule" {
  description = "Cron schedule for the CISA KEV vuln sync (UTC)"
  type        = string
  default     = "40 7 * * *"
}

variable "vuln_sync_osv_schedule" {
  description = "Cron schedule for the OSV cross-check vuln sync (UTC)"
  type        = string
  default     = "10 8 * * 1"
}

# Daily, and well clear of the nvd job's :20 — the two share one advisory lock.
# Scheduled deliberately: see ADR-002.
variable "vuln_sync_cvss_schedule" {
  description = "Cron schedule for the CVSS enrichment repair pass (UTC)"
  type        = string
  default     = "10 9 * * *"
}

# Runs after the nvd job's :20 so a newly seeded package is swept the same day.
variable "vuln_backfill_auto_schedule" {
  description = "Cron schedule for the autonomous per-package CVE backfill sweep (UTC)"
  type        = string
  default     = "50 6 * * *"
}

# 3600s was a default nobody had revisited, and it does not survive a first backfill: onboarding
# IntelliJ alone transfers 25.8 GB across 16 artifacts, which at 8 concurrent streams and a
# conservative 50 Mbps aggregate is over an hour before any other package is touched. 6h leaves
# room for a slow upstream without approaching the 24h job maximum. Steady-state incremental
# syncs are minutes, so this bounds only the pathological run.
variable "sync_job_timeout" {
  description = "Max duration for one walrus-sync Cloud Run Job execution"
  type        = string
  default     = "21600s"
}

variable "sql_deletion_protection" {
  description = "Enable deletion protection on the Cloud SQL instance (set to false for teardown)"
  type        = bool
  default     = true
}

variable "gcs_force_destroy" {
  description = "Allow Terraform to delete the GCS bucket even if it contains objects (set to true for teardown)"
  type        = bool
  default     = false
}
