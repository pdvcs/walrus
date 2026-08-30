resource "google_secret_manager_secret" "database_url" {
  secret_id = "walrus-database-url"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "session_secret" {
  secret_id = "walrus-session-secret"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "session_secret_previous" {
  secret_id = "walrus-session-secret-previous"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret" "admin_password" {
  secret_id = "walrus-admin-password"

  replication {
    auto {}
  }
}
