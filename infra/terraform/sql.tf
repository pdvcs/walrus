resource "google_sql_database_instance" "walrus" {
  name             = "walrus-postgres"
  database_version = "POSTGRES_18"
  region           = var.region

  settings {
    tier    = var.cloud_sql_tier
    edition = "ENTERPRISE"
    ip_configuration {
      ipv4_enabled = true
    }
  }

  deletion_protection = var.sql_deletion_protection
}

resource "google_sql_database" "walrus" {
  name     = "walrus"
  instance = google_sql_database_instance.walrus.name
}

resource "google_sql_user" "walrus" {
  name     = "walrus"
  instance = google_sql_database_instance.walrus.name
  password = var.cloud_sql_db_password
}
