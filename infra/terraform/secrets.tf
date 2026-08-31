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

# Upstream GitHub credential (WAL-103). Discovery for gitwindows, python, ripgrep and uv calls
# api.github.com, which allows 60 requests/hour per IP unauthenticated — and Cloud Run's egress
# address is shared with other tenants, so that budget is not even walrus's alone to spend. It
# ran out on 2026-08-31 and failed a scheduled sync outright, taking four packages' freshness
# with it. A token raises the limit to 5,000/hour.
#
# Same shape as the NVD key above and for the same reason: declared unconditionally so the IAM
# binding and rotation path exist from the first apply, populated by deploy.sh only when
# GITHUB_TOKEN is supplied, and mounted only when var.github_token_configured says a version
# exists. A fresh project still bootstraps without one, just at the unauthenticated limit.
resource "google_secret_manager_secret" "github_token" {
  secret_id = "walrus-github-token"

  replication {
    auto {}
  }
}
