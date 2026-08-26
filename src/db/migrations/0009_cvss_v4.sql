-- CVSS v4 support.
--
-- `extractCvss` previously read only cvssMetricV31/V30/V2, so CVEs scored solely
-- under CVSS v4.0 — increasingly the only score a CNA publishes, and all NVD's
-- "Deferred" backlog will ever carry — landed with severity NULL and were then
-- terminally marked 'nvd-no-metrics' by the enrichment pass, despite NVD holding
-- a usable score. Columns are nullable and additive; existing rows are untouched
-- except as backfilled below.
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cvss_v4_score  NUMERIC(3,1);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cvss_v4_vector TEXT;

-- Backfill v4 columns for rows whose v4 metrics are already stored in `raw`,
-- avoiding an NVD re-walk. Unlike v2, v4 keeps baseSeverity inside cvssData.
-- The columns are independent of v3/v2, so this applies to every row with v4
-- metrics, scored elsewhere or not.
UPDATE cves SET
  cvss_v4_score  = (raw->'cve'->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseScore')::numeric(3,1),
  cvss_v4_vector =  raw->'cve'->'metrics'->'cvssMetricV40'->0->'cvssData'->>'vectorString'
WHERE raw->'cve'->'metrics' ? 'cvssMetricV40';

-- Rows that are v4-only get their severity from v4. The severity IS NULL guard
-- keeps this idempotent and away from anything already scored under v3/v2; it
-- also overwrites an 'nvd-no-metrics' sentinel, which for these rows recorded a
-- reader limitation, not an upstream fact.
UPDATE cves SET
  severity        = raw->'cve'->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseSeverity',
  severity_source = 'nvd-cvss-v4'
WHERE severity IS NULL
  AND raw->'cve'->'metrics'->'cvssMetricV40'->0->'cvssData'->>'baseSeverity' IS NOT NULL;

-- Remaining 'nvd-no-metrics' sentinels were written by an enrichment pass that
-- could not see v4 metrics in NVD's by-id response (the response is not stored
-- in `raw` for OSV stubs, so it cannot be backfilled locally). Reset them to
-- candidates; the next scheduled cvss run re-fetches each once, now reading v4,
-- and re-marks the genuinely unscored ones.
UPDATE cves SET severity_source = NULL
WHERE severity IS NULL AND severity_source = 'nvd-no-metrics';
