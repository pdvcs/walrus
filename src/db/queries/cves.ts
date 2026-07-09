import { Pool } from "pg";
import { Queryable } from "../queryable.js";

// ── Row / input shapes ──────────────────────────────────────────────────────

export interface CveRow {
  id: string;
  published_at: Date | null;
  modified_at: Date | null;
  cvss_v3_score: string | null; // NUMERIC comes back as string from pg
  cvss_v3_vector: string | null;
  severity: string | null;
  description: string | null;
  is_kev: boolean;
  kev_added_at: Date | null;
  raw: unknown;
  updated_at: Date | null;
}

export interface CveUpsert {
  id: string;
  published_at: string | null;
  modified_at: string | null;
  cvss_v3_score: number | null;
  cvss_v3_vector: string | null;
  severity: string | null;
  description: string | null;
  raw: unknown;
}

export interface CveStub {
  id: string;
  published_at: string | null;
  modified_at: string | null;
  description: string | null;
  raw: unknown;
}

export interface AffectsInsert {
  cve_id: string;
  package_name: string;
  version_start: string | null;
  version_start_excl: boolean;
  version_end: string | null;
  version_end_excl: boolean;
  exact_version: string | null;
  fixed_in: string | null;
  source: "nvd" | "osv";
  raw_cpe: string | null;
}

/** Join of a cve_affects row with its parent CVE's denormalized fields. */
export interface AffectsWithCveRow {
  cve_id: string;
  version_start: string | null;
  version_start_excl: boolean;
  version_end: string | null;
  version_end_excl: boolean;
  exact_version: string | null;
  fixed_in: string | null;
  source: string;
  severity: string | null;
  cvss_v3_score: string | null;
  description: string | null;
  is_kev: boolean;
  raw: { cve?: { references?: Array<{ url: string }> } } | null;
}

export interface AffectedPackageRow {
  package_name: string;
  display_name: string;
  version_start: string | null;
  version_start_excl: boolean;
  version_end: string | null;
  version_end_excl: boolean;
  exact_version: string | null;
  fixed_in: string | null;
  source: string;
}

// ── Upserts ─────────────────────────────────────────────────────────────────

/** Full CVE upsert (NVD ingestion): overwrites denormalized fields + raw. */
export async function upsertCveFull(q: Queryable, cve: CveUpsert): Promise<void> {
  await q.query(
    `INSERT INTO cves (id, published_at, modified_at, cvss_v3_score, cvss_v3_vector, severity, description, raw, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
     ON CONFLICT (id) DO UPDATE SET
       published_at   = EXCLUDED.published_at,
       modified_at    = EXCLUDED.modified_at,
       cvss_v3_score  = EXCLUDED.cvss_v3_score,
       cvss_v3_vector = EXCLUDED.cvss_v3_vector,
       severity       = EXCLUDED.severity,
       description    = EXCLUDED.description,
       raw            = EXCLUDED.raw,
       updated_at     = now()`,
    [
      cve.id,
      cve.published_at,
      cve.modified_at,
      cve.cvss_v3_score,
      cve.cvss_v3_vector,
      cve.severity,
      cve.description,
      JSON.stringify(cve.raw),
    ],
  );
}

/**
 * Stub CVE insert (OSV-only CVEs NVD may not have yet). Does NOT overwrite an
 * existing row — NVD ingestion owns the full record. Returns 1 if a new stub was
 * created, 0 if the CVE already existed.
 */
export async function upsertCveStub(q: Queryable, cve: CveStub): Promise<number> {
  const res = await q.query(
    `INSERT INTO cves (id, published_at, modified_at, description, raw)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (id) DO NOTHING`,
    [cve.id, cve.published_at, cve.modified_at, cve.description, JSON.stringify(cve.raw)],
  );
  return res.rowCount ?? 0;
}

// ── Affects ─────────────────────────────────────────────────────────────────

/** Drop all affects rows for a CVE from one source (rebuild-per-cve on re-sync). */
export async function deleteAffectsForSource(
  q: Queryable,
  cveId: string,
  source: "nvd" | "osv",
): Promise<void> {
  await q.query(`DELETE FROM cve_affects WHERE cve_id = $1 AND source = $2`, [cveId, source]);
}

/** Insert one affects row, deduped by the UNIQUE NULLS NOT DISTINCT constraint. */
export async function insertAffects(q: Queryable, row: AffectsInsert): Promise<number> {
  const res = await q.query(
    `INSERT INTO cve_affects
       (cve_id, package_name, version_start, version_start_excl, version_end, version_end_excl, exact_version, fixed_in, source, raw_cpe)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
     ON CONFLICT ON CONSTRAINT cve_affects_dedupe DO NOTHING`,
    [
      row.cve_id,
      row.package_name,
      row.version_start,
      row.version_start_excl,
      row.version_end,
      row.version_end_excl,
      row.exact_version,
      row.fixed_in,
      row.source,
      row.raw_cpe,
    ],
  );
  return res.rowCount ?? 0;
}

// ── KEV flagging ────────────────────────────────────────────────────────────

/** Which of the given CVE ids exist in our table. */
export async function knownCveIds(q: Queryable, ids: string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const { rows } = await q.query<{ id: string }>(`SELECT id FROM cves WHERE id = ANY($1)`, [ids]);
  return new Set(rows.map((r) => r.id));
}

/** Set the KEV flag + date on one CVE (no-op if already set to the same values). */
export async function flagKev(q: Queryable, cveId: string, addedAt: string): Promise<void> {
  await q.query(
    `UPDATE cves SET is_kev = TRUE, kev_added_at = $2, updated_at = now()
     WHERE id = $1 AND (is_kev IS DISTINCT FROM TRUE OR kev_added_at IS DISTINCT FROM $2::date)`,
    [cveId, addedAt],
  );
}

/** Clear the KEV flag on any CVE not in the given id set. Returns rows cleared. */
export async function clearKevExcept(q: Queryable, ids: string[]): Promise<number> {
  const res = await q.query(
    `UPDATE cves SET is_kev = FALSE, kev_added_at = NULL, updated_at = now()
     WHERE is_kev = TRUE AND NOT (id = ANY($1))`,
    [ids],
  );
  return res.rowCount ?? 0;
}

// ── Reads ───────────────────────────────────────────────────────────────────

export async function getCveById(pool: Pool, id: string): Promise<CveRow | null> {
  const { rows } = await pool.query<CveRow>(
    `SELECT id, published_at, modified_at, cvss_v3_score, cvss_v3_vector, severity,
            description, is_kev, kev_added_at, raw, updated_at
     FROM cves WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

/** All affects rows (joined to CVE metadata) for one package — powers /vulns and cross-ref. */
export async function listAffectsWithCveForPackage(
  pool: Pool,
  packageName: string,
): Promise<AffectsWithCveRow[]> {
  const { rows } = await pool.query<AffectsWithCveRow>(
    `SELECT ca.cve_id, ca.version_start, ca.version_start_excl, ca.version_end,
            ca.version_end_excl, ca.exact_version, ca.fixed_in, ca.source,
            c.severity, c.cvss_v3_score, c.description, c.is_kev, c.raw
     FROM cve_affects ca JOIN cves c ON c.id = ca.cve_id
     WHERE ca.package_name = $1
     ORDER BY ca.cve_id DESC`,
    [packageName],
  );
  return rows;
}

/** Affected packages (joined to display name) for one CVE — powers CVE detail. */
export async function listAffectedPackagesForCve(
  pool: Pool,
  cveId: string,
): Promise<AffectedPackageRow[]> {
  const { rows } = await pool.query<AffectedPackageRow>(
    `SELECT ca.package_name, p.display_name, ca.version_start, ca.version_start_excl,
            ca.version_end, ca.version_end_excl, ca.exact_version, ca.fixed_in, ca.source
     FROM cve_affects ca JOIN packages p ON p.name = ca.package_name
     WHERE ca.cve_id = $1 ORDER BY ca.package_name`,
    [cveId],
  );
  return rows;
}
