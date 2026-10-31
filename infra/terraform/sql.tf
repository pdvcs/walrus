resource "google_sql_database_instance" "walrus" {
  name             = "walrus-postgres"
  database_version = "POSTGRES_18"
  region           = var.region

  settings {
    tier    = var.cloud_sql_tier
    edition = "ENTERPRISE"

    # Pinned, not inherited: the Cloud Run connection budget in cloudrun.tf divides this number,
    # and it was previously the tier's undocumented default (~25 for db-f1-micro). Changing it
    # restarts the instance. Raising the tier without raising this leaves the extra memory unused
    # by connections; the service's precondition will not catch that, because it only guards
    # over-subscription.
    database_flags {
      name  = "max_connections"
      value = tostring(var.db_max_connections)
    }
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
