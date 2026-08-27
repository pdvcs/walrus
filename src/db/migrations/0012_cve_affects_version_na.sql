-- Record CPE 2.3 NA (`-`) in the version component distinctly from ANY (`*`) — WAL-69.
--
-- The two are different logical values: `*` means the entry applies to ANY version, `-` means
-- the version attribute does not apply to this entry at all. Ingestion collapsed both into an
-- affects row with no bounds, which `evaluateRange` reads as "all versions" — right for ANY,
-- wrong for NA. CNAs use NA when filing against a product they cannot version (hosted services,
-- and extensions that are not the product itself), so an advisory naming no version blocked
-- every version: CVE-2024-43488 is an Arduino *extension* flaw filed against VS Code itself.
--
-- The flag is set at ingest from the parsed CPE rather than derived from `raw_cpe` at read time,
-- because splitting on colons is wrong for components carrying escaped ones and because the gate
-- should not re-parse a CPE for every version it evaluates.

ALTER TABLE cve_affects
  ADD COLUMN IF NOT EXISTS version_na BOOLEAN NOT NULL DEFAULT false;

-- Backfill what is already ingested. Best-effort by design: NVD re-sync rebuilds a CVE's 'nvd'
-- affects rows wholesale, so any row this misses (an escaped colon in vendor or product shifting
-- the component index) is corrected by ingestion on the next run. `raw_cpe` carries an optional
-- `|>=x,<y` range suffix, which is stripped before indexing. OSV rows have no raw_cpe and are
-- untouched.
UPDATE cve_affects
   SET version_na = true
 WHERE source = 'nvd'
   AND raw_cpe IS NOT NULL
   AND split_part(split_part(raw_cpe, '|', 1), ':', 6) = '-';

-- Partial index: the gate's only question is which rows to skip, and NA rows are a small
-- minority of any package's affects.
CREATE INDEX IF NOT EXISTS idx_cve_affects_version_na
  ON cve_affects(package_name)
  WHERE version_na;
