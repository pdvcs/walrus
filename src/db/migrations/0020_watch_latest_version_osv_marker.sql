-- Latest-version lookup for watch-only packages, and a per-package OSV coverage marker (WAL-54).
--
-- Walrus discovers no versions for a watch-only package, so it cannot say which release is
-- current — and "is the current release affected?" is the question the watchlist exists to
-- answer. latest_version is resolved from a small [latest] block in the watchlist TOML by a
-- scheduled refresh, not by discovery, and is stored here rather than in `versions` so a
-- watch package still owns no version or artifact rows.
--   latest_version             last successfully resolved version (kept across failures)
--   latest_version_checked_at  last attempt, success or failure
--   latest_version_error       reason the last attempt failed; NULL after a success
--
-- osv_synced_at records that OSV was queried for this package at least once. Without it an
-- empty result cannot be told apart from "never looked": a posture of "clean" must mean
-- every configured source has actually been consulted. The NVD half of that question is
-- already answered by vuln_backfill_completed_at (0007).

ALTER TABLE packages
  ADD COLUMN IF NOT EXISTS latest_version TEXT,
  ADD COLUMN IF NOT EXISTS latest_version_checked_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS latest_version_error TEXT,
  ADD COLUMN IF NOT EXISTS osv_synced_at TIMESTAMPTZ;

-- Packages that already hold OSV-sourced advisories were demonstrably read from OSV before this
-- column existed; marking them avoids reporting every established package as "coverage
-- incomplete" until the next weekly cross-check. Deliberately NOT inferred from the global OSV
-- sync state: a package whose mapping was added after that run was never queried, and calling
-- it covered would turn "unknown" into a false "clean". A mapped package with zero advisories
-- stays unmarked (unknown) until its first real sync — the conservative direction.
UPDATE packages p
   SET osv_synced_at = now()
 WHERE p.osv_ecosystem IS NOT NULL
   AND p.osv_synced_at IS NULL
   AND EXISTS (SELECT 1 FROM cve_affects a WHERE a.package_name = p.name AND a.source = 'osv');
