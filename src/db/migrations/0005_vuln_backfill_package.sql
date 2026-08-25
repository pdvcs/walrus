-- Targeted backfill: scope a vuln_backfill_jobs row to a single package.
-- NULL (the default, and every pre-existing row) means "all tracked CPE pairs",
-- so the full-backfill behaviour is unchanged.
--
-- The one-active-job index is deliberately left global: NVD ingestion is already
-- serialized by withVulnSyncLock('nvd'), so two concurrent backfills — targeted
-- or not — could never actually overlap.
ALTER TABLE vuln_backfill_jobs
    ADD COLUMN IF NOT EXISTS package_name TEXT REFERENCES packages(name) ON DELETE CASCADE;
