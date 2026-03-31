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

variable "sync_schedule" {
  description = "Cron schedule for Cloud Scheduler sync job (UTC)"
  type        = string
  default     = "0 */6 * * *"
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
