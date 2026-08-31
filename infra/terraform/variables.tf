variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "alert_notification_email" {
  description = "Email address for Walrus operational alerts; deploy.sh derives the sole project owner when unset"
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

# ── Cloud SQL connection budget ────────────────────────────────────────────────────────────────
#
# Four numbers that must move together, so they live together. The invariant is enforced by a
# precondition on the Cloud Run service in cloudrun.tf, so a config that over-subscribes the
# database fails at plan time rather than at 3am:
#
#   service_db_pool_max x cloud_run_max_instances  +  job_db_pool_max x 2  <=  usable
#
# where `usable` is derived, not declared: db_max_connections - db_reserved_connections. Deriving
# it means the budget cannot silently disagree with what Postgres is actually configured to allow.
#
# The defaults below size a **test** environment on the db-f1-micro default: 3 x 4 + 4 x 2 = 20.
# UAT and production should raise the Cloud SQL tier first and then all four of these together --
# raising the ceiling alone silently throttles the service, and raising it with the pools but not
# the tier exhausts Postgres, where a scale-up becomes the outage instead of relieving it.
# Sizing the real tiers is deliberately deferred; see plans/gcp-testing-tasks.md.

# Pinned via databaseFlags in sql.tf rather than inherited: the whole budget divides this number,
# and a tier default is not something to divide by. db-f1-micro's default is ~25; setting it makes
# the divisor deterministic and survives a tier change being made without re-reading this block.
# NOTE: changing this restarts the Cloud SQL instance.
variable "db_max_connections" {
  description = "Postgres max_connections, pinned on the instance (see sql.tf)"
  type        = number
  default     = 25
}

# Not available to walrus: Postgres' own superuser_reserved_connections (default 3) plus the
# sessions Cloud SQL's management agents hold. Five is deliberately a little generous — running the
# database to its literal ceiling turns a routine admin query into a failed one.
variable "db_reserved_connections" {
  description = "Connections held back from the pool budget for superuser and Cloud SQL management"
  type        = number
  default     = 5
}

variable "service_db_pool_max" {
  description = "Connections each walrus-api instance may hold (multiplied by cloud_run_max_instances)"
  type        = number
  default     = 3
}

variable "job_db_pool_max" {
  description = "Connections each Cloud Run Job execution may hold (one execution at a time per job)"
  type        = number
  default     = 4
}

# Left unset, Cloud Run's default ceiling is 100 instances -- with pg's default pool of 10 that is
# ~1,000 connections against a db-f1-micro's ~25, so a traffic spike would make Cloud Run scale up
# and every new instance would then fail to reach Postgres.
variable "cloud_run_max_instances" {
  description = "Maximum Cloud Run instances; bounded by the connection budget above"
  type        = number
  default     = 4
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

# How many un-scored CVEs one scheduled cvss run may walk (WAL-48). Bounded because enrichment
# issues one NVD request per candidate and the run must finish inside the job's attempt deadline:
#
#   keyless   4 req / 30s = 0.133/s x 1800s deadline = ~240 requests, theoretical ceiling
#   with key 45 req / 30s = 1.5/s   x 1800s deadline = ~2700
#
# The default is sized for the *keyless* case, deliberately under that 240: NVD_API_KEY is
# optional (WAL-92), so a deployment without one must still finish rather than be cut off
# mid-walk. The walk is resumable -- a deadline-exceeded run simply continues from the remaining
# candidates next time -- so the cost of being conservative is latency in draining the backlog,
# not lost work. An environment with a key can raise this an order of magnitude.
variable "vuln_sync_cvss_limit" {
  description = "Max CVEs one scheduled cvss enrichment run may walk (sized for keyless NVD; see comment)"
  type        = number
  default     = 150
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

# Cloud Run Jobs default to deletion_protection = true in the provider, which the service opts
# out of but the Jobs never did — so `terraform destroy` aborted on both of them and left a
# half-torn-down project behind, with Cloud SQL and the bucket already stripped of their own
# protection by teardown.sh's targeted apply. Found by the first real plan (WAL-40, 2026-08-30).
# Defaults to protected; teardown.sh lowers it the same way it lowers the other two.
variable "job_deletion_protection" {
  description = "Enable deletion protection on the Cloud Run Jobs (set to false for teardown)"
  type        = bool
  default     = true
}

variable "gcs_force_destroy" {
  description = "Allow Terraform to delete the GCS bucket even if it contains objects (set to true for teardown)"
  type        = bool
  default     = false
}

# Set automatically by deploy.sh from the presence of NVD_API_KEY (WAL-92 AC4); the key is
# optional, so a fresh project can bootstrap keyless exactly as local dev does. This gates the
# secret_key_ref, not the secret itself: Cloud Run refuses to deploy a revision whose referenced
# secret has no versions, so wiring the reference unconditionally would turn an unsupplied key
# from a slower NVD walk into a hard deploy failure.
variable "nvd_api_key_configured" {
  description = "Whether walrus-nvd-api-key holds a version to mount into the workloads"
  type        = bool
  default     = false
}

# Set automatically by deploy.sh from the presence of GITHUB_TOKEN (WAL-103). Gates the
# secret_key_ref rather than the secret, for the same reason as the NVD flag above: a reference
# to a secret with no versions is a hard deploy failure, and an absent token should only mean a
# lower rate limit.
variable "github_token_configured" {
  description = "Whether walrus-github-token holds a version to mount into the sync job"
  type        = bool
  default     = false
}
