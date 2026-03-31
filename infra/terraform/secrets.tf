resource "google_secret_manager_secret" "database_url" {
  secret_id = "walrus-database-url"

  replication {
    auto {}
  }
}
