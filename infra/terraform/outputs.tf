output "cloud_run_url" {
  description = "URL of the deployed Cloud Run service"
  value       = google_cloud_run_v2_service.walrus.uri
}

output "artifact_registry_image_base" {
  description = "Base image path in Artifact Registry"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/walrus/walrus-api"
}

output "gcs_bucket" {
  description = "Name of the GCS artifact bucket"
  value       = google_storage_bucket.artifacts.name
}
