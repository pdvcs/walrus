-- Core package registry (mirrors TOML config, used for runtime queries)
CREATE TABLE packages (
    name            TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    vendor          TEXT NOT NULL,
    description     TEXT,
    website         TEXT,
    config_hash     TEXT NOT NULL,
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- Discovered versions
CREATE TABLE versions (
    id              SERIAL PRIMARY KEY,
    package_name    TEXT NOT NULL REFERENCES packages(name),
    version         TEXT NOT NULL,
    version_group   TEXT NOT NULL,
    is_lts          BOOLEAN DEFAULT false,
    discovered_at   TIMESTAMPTZ DEFAULT now(),
    version_sort    TEXT NOT NULL,
    UNIQUE(package_name, version)
);
CREATE INDEX idx_versions_pkg_group ON versions(package_name, version_group);

-- Binary artifacts (one per version+platform combination)
CREATE TABLE artifacts (
    id              SERIAL PRIMARY KEY,
    version_id      INTEGER NOT NULL REFERENCES versions(id) ON DELETE CASCADE,
    os              TEXT NOT NULL,
    arch            TEXT NOT NULL,
    filename        TEXT NOT NULL,
    gcs_path        TEXT,
    file_size       BIGINT,
    checksum        TEXT,
    checksum_type   TEXT,
    upstream_url    TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    sync_job_id     INTEGER,  -- FK added after sync_jobs table
    cooling_off_until TIMESTAMPTZ,
    download_started_at   TIMESTAMPTZ,
    download_completed_at TIMESTAMPTZ,
    removed_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now(),
    UNIQUE(version_id, os, arch)
);
CREATE INDEX idx_artifacts_status ON artifacts(status);
CREATE INDEX idx_artifacts_gcs ON artifacts(gcs_path) WHERE gcs_path IS NOT NULL;

-- Sync/discovery job tracking
CREATE TABLE sync_jobs (
    id                  SERIAL PRIMARY KEY,
    package_name        TEXT NOT NULL REFERENCES packages(name),
    trigger_type        TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'running',
    versions_found      INTEGER DEFAULT 0,
    artifacts_queued    INTEGER DEFAULT 0,
    artifacts_downloaded INTEGER NOT NULL DEFAULT 0,
    artifacts_failed    INTEGER NOT NULL DEFAULT 0,
    error_message       TEXT,
    started_at          TIMESTAMPTZ DEFAULT now(),
    completed_at        TIMESTAMPTZ
);

-- Add FK from artifacts to sync_jobs now that both tables exist
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_sync_job_id_fkey
    FOREIGN KEY (sync_job_id) REFERENCES sync_jobs(id) ON DELETE SET NULL;

CREATE INDEX idx_artifacts_sync_job ON artifacts(sync_job_id)
    WHERE sync_job_id IS NOT NULL;

-- Admin action audit log
CREATE TABLE admin_actions (
    id              SERIAL PRIMARY KEY,
    action_type     TEXT NOT NULL,
    package_name    TEXT,
    version         TEXT,
    artifact_id     INTEGER REFERENCES artifacts(id),
    performed_by    TEXT,
    details         JSONB,
    created_at      TIMESTAMPTZ DEFAULT now()
);
