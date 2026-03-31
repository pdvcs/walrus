resource "google_artifact_registry_repository" "walrus" {
  location      = var.region
  repository_id = "walrus"
  format        = "DOCKER"
  description   = "Walrus API Docker images"
}
