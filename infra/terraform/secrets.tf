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

# Upstream NVD API 2.0 credential (WAL-92) — not a walrus principal. It raises NVD's rate limit
# from 5 to 50 requests / 30s, which is the difference between a historical backfill measured in
# minutes and one measured in hours. Declared unconditionally so the IAM binding and the rotation
# path exist from the first apply; populated by deploy.sh only when NVD_API_KEY is supplied, and
# mounted into the workloads only when var.nvd_api_key_configured says a version exists. A secret
# with no versions is free and lets a fresh project bootstrap keyless.
resource "google_secret_manager_secret" "nvd_api_key" {
  secret_id = "walrus-nvd-api-key"

  replication {
    auto {}
  }
}
