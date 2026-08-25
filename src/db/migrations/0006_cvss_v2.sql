-- CVSS v2 support + severity provenance.
--
-- `extractCvss` previously read only cvssMetricV31/V30, so CVEs scored solely
-- under CVSS v2 (mostly pre-2015) landed with severity NULL and were invisible
-- to the severity counts. Columns are nullable and additive; existing v3 rows
-- are untouched.
--
-- severity_source records WHICH CVSS version produced `severity`, because the
-- two are not comparable: v2 has no CRITICAL band (v2 HIGH spans 7.0-10.0,
-- while v3 splits HIGH 7.0-8.9 / CRITICAL 9.0+).
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cvss_v2_score   NUMERIC(3,1);
ALTER TABLE cves ADD COLUMN IF NOT EXISTS cvss_v2_vector  TEXT;
ALTER TABLE cves ADD COLUMN IF NOT EXISTS severity_source TEXT;

-- Backfill rows whose v2 metrics are already stored in `raw`, avoiding an NVD
-- re-walk. NVD puts v2's baseSeverity on the metric object rather than inside
-- cvssData, hence the coalesce. The severity IS NULL guard keeps this
-- idempotent and stops it touching anything already scored from v3.
UPDATE cves SET
  cvss_v2_score   = (raw->'cve'->'metrics'->'cvssMetricV2'->0->'cvssData'->>'baseScore')::numeric(3,1),
  cvss_v2_vector  =  raw->'cve'->'metrics'->'cvssMetricV2'->0->'cvssData'->>'vectorString',
  severity        = coalesce(raw->'cve'->'metrics'->'cvssMetricV2'->0->>'baseSeverity',
                             raw->'cve'->'metrics'->'cvssMetricV2'->0->'cvssData'->>'baseSeverity'),
  severity_source = 'nvd-cvss-v2'
WHERE severity IS NULL
  AND raw->'cve'->'metrics' ? 'cvssMetricV2';

-- Existing v3-scored rows predate the provenance column; label them.
UPDATE cves SET severity_source = 'nvd-cvss-v3'
WHERE severity_source IS NULL AND severity IS NOT NULL;
