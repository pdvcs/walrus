-- Operator waivers for the release embargo (retention.cooling_off_days). An urgent upstream fix
-- cannot wait out its cooling-off period, and the embargo is recomputed on every sync, so a
-- one-off edit of artifacts.cooling_off_until would be rewritten by the next run. A waiver is a
-- durable, audited assertion that sync consults when it computes the embargo.
-- There is deliberately no expires_at: the embargo ends by itself, and a waiver for a version
-- that is no longer embargoed is inert.

CREATE TABLE IF NOT EXISTS cooling_off_waivers (
  id            SERIAL PRIMARY KEY,
  package_name  TEXT NOT NULL REFERENCES packages(name) ON DELETE CASCADE,
  version       TEXT NOT NULL CHECK (length(btrim(version)) > 0),
  reason        TEXT NOT NULL CHECK (length(btrim(reason)) > 0),
  created_by    TEXT NOT NULL CHECK (length(btrim(created_by)) > 0),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS cooling_off_waivers_unrevoked_version
  ON cooling_off_waivers (package_name, version)
  WHERE revoked_at IS NULL;
