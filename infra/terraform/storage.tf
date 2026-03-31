resource "google_storage_bucket" "artifacts" {
  name                        = var.gcs_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = var.gcs_force_destroy
}
