-- Operator suppression list for CVEs that are correctly shaped but mis-attributed in fact
-- (WAL-70). Suppressions are operational assertions with an independent lifecycle, so they
-- survive cve_affects rows being deleted and rebuilt during ingestion.

CREATE TABLE IF NOT EXISTS cve_suppressions (
  id            SERIAL PRIMARY KEY,
  cve_id        TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
  -- NULL applies the assertion to every package affected by this CVE.
  package_name  TEXT REFERENCES packages(name) ON DELETE CASCADE,
  reason        TEXT NOT NULL CHECK (length(btrim(reason)) > 0),
  created_by    TEXT NOT NULL CHECK (length(btrim(created_by)) > 0),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at    TIMESTAMPTZ,
  revoked_at    TIMESTAMPTZ
);

-- Only one unrevoked assertion per scope. An expired row is revoked transactionally before a
-- replacement is inserted, retaining its history without making expiry depend on a sweep.
CREATE UNIQUE INDEX IF NOT EXISTS cve_suppressions_unrevoked_scope
  ON cve_suppressions (cve_id, package_name) NULLS NOT DISTINCT
  WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cve_suppressions_active
  ON cve_suppressions (cve_id, package_name)
  WHERE revoked_at IS NULL;
