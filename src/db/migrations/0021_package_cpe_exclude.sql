-- Per-package CPE exclusions (`[vulnerabilities].cpe_exclude`).
--
-- NVD sometimes files a different product under a pair a package tracks, telling the two apart
-- only by a CPE qualifier component: Terraform Enterprise is hashicorp:terraform with target_sw
-- "enterprise", and the Ruby `git` gem is git:git with target_sw "ruby". Matching on
-- vendor:product alone attributed those CVEs to the Terraform CLI and Git for Windows, including
-- CRITICAL ones the download gate acts on.
--
--   cpe_exclude  JSON array of rules, each an object of qualifier component -> value; a CPE is
--                excluded for this package when every component in some rule equals its value.
--                NULL = no exclusions.
--
-- Reconciled from the TOML on boot, exactly as osv_ecosystem / osv_name / cve_version_extract
-- are. Reconcile also deletes stored NVD rows the rules now exclude, so changing a rule takes
-- effect without re-ingesting.

ALTER TABLE packages ADD COLUMN IF NOT EXISTS cpe_exclude JSONB;
