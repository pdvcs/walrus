-- Score provenance for availability transitions (review walrus-0826-review-02.md §3.1).
--
-- The critical gate blocks on ANY CVSS base score >= 9.0 (v3, v4, or v2) plus the
-- score-less CRITICAL fallback (ADR-005). These columns existed only for v3, so an
-- event recorded by a v4-only CVE — e.g. one showing v3 8.1/HIGH while v4 scored 9.1
-- could not explain its own 'blocked' status: the recorded evidence would not have
-- blocked under any version of the policy.
--
-- Columns are nullable and additive. Existing rows are deliberately NOT backfilled:
-- they recorded the blocking CVE's state at transition time, and cves scores move, so
-- joining today's cves would rewrite history into a mixture of two timeframes. A row
-- predating this migration reports its era's truth — v3-era evidence — which may not
-- state the full reason under the later any-of policy; that gap closes going forward,
-- as every new insert carries all stored scores plus the producing source.

ALTER TABLE version_availability_events
  ADD COLUMN IF NOT EXISTS cvss_v4_score NUMERIC(3,1);
ALTER TABLE version_availability_events
  ADD COLUMN IF NOT EXISTS cvss_v2_score NUMERIC(3,1);
ALTER TABLE version_availability_events
  ADD COLUMN IF NOT EXISTS severity_source TEXT;
