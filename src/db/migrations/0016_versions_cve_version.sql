-- Per-version CVE version override (ADR-008 generalised).
--
-- ADR-008 normalises a served version to the upstream version it embeds using a per-package
-- regex (cve_version_extract). That works when the mapping is fixed — Git for Windows rebuild
-- numbers are always the last component. The .NET SDK is different: NVD files its CVEs against
-- the bundled runtime, and the SDK-to-runtime mapping changes per release (SDK 10.0.401 bundles
-- runtime 10.0.12, SDK 10.0.400 bundles 10.0.11). A regex cannot express it, so discovery carries
-- the mapping out per version and it is stored here.
--
--   cve_version  the version to compare against CVE ranges, when it differs from the served
--                version. NULL = derive with cve_version_extract, or compare the served version
--                directly, exactly as before this column existed.
--
-- Only range evaluation sees this value: the served version, version_sort, retention and the
-- download path all continue to use the full version.

ALTER TABLE versions ADD COLUMN IF NOT EXISTS cve_version TEXT;
