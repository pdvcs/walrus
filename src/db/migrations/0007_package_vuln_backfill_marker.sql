-- Per-package historical-backfill marker (WAL-37).
--
-- Incremental NVD sync is cursor-based on lastModStartDate, so it only ever sees
-- recently-modified CVEs. A package whose CPE pairs appear after the first backfill
-- can never acquire its historical CVEs from it — only a targeted backfill reaches
-- them, and nothing triggered one automatically.
--
-- The marker records the *CPE set* that was backfilled, not merely that a backfill
-- happened. Counting cve_affects rows cannot distinguish "never backfilled" from
-- "backfilled, found nothing", and a plain timestamp cannot tell that a new CPE pair
-- was added to a package that was already covered.

ALTER TABLE packages
  ADD COLUMN IF NOT EXISTS vuln_backfill_cpe_hash TEXT,
  ADD COLUMN IF NOT EXISTS vuln_backfill_completed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS vuln_backfill_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS vuln_backfill_last_error TEXT;

-- Partial index: the autostart sweep only ever looks at packages that have not been
-- covered for their current CPE set.
CREATE INDEX IF NOT EXISTS idx_packages_vuln_backfill_pending
  ON packages(name)
  WHERE vuln_backfill_completed_at IS NULL;
