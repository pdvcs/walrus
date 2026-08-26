-- Version-level availability history (WAL-36, ADR-003 commitment 3).
--
-- The critical-CVE gate is a pure predicate evaluated on read, so nothing anywhere
-- recorded *when* a version became download-blocked or *why*. With ingestion now
-- unattended (ADR-002/ADR-003), a scheduled run can turn a served version into a 403
-- with no human present, and "what blocked this, and when?" had to be reconstructed by
-- hand from cves.updated_at and the affects rows.
--
-- Rows are transitions, not states: one is written only when a version's gate status
-- actually flips. A version that stays available forever produces none.

CREATE TABLE IF NOT EXISTS version_availability_events (
  id             BIGSERIAL PRIMARY KEY,
  package_name   TEXT NOT NULL REFERENCES packages(name) ON DELETE CASCADE,
  version        TEXT NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('blocked', 'available')),
  -- Which CVE caused a 'blocked' transition. NULL on 'available' — nothing causes
  -- a version to become servable except the absence of a blocking match.
  cve_id         TEXT,
  cvss_v3_score  NUMERIC(3,1),
  severity       TEXT,
  -- Attribution: which ingestion produced the change, and how it was triggered.
  -- 'trigger' is reserved in Postgres, hence trigger_type.
  source         TEXT NOT NULL,
  trigger_type   TEXT NOT NULL,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- The lookup this table exists for: the history of one version, newest first.
CREATE INDEX IF NOT EXISTS idx_vae_pkg_version
  ON version_availability_events(package_name, version, id DESC);

-- "What changed recently?", across all packages.
CREATE INDEX IF NOT EXISTS idx_vae_created
  ON version_availability_events(created_at DESC);
