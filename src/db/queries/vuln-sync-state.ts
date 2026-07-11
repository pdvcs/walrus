import { Pool } from "pg";
import { Queryable } from "../queryable.js";

export type VulnSyncSource = "nvd-cve" | "kev" | "osv";

export interface VulnSyncStateRow {
  source: string;
  cursor: string | null;
  last_run: Date | null;
  last_ok: boolean | null;
  last_success_at: Date | null;
  last_failure_at: Date | null;
}

export interface VulnSourceStatus {
  last_attempt: string | null;
  last_success: string | null;
  last_failure: string | null;
  last_ok: boolean | null;
}

export interface VulnSyncStatus {
  nvd: VulnSourceStatus;
  kev: VulnSourceStatus;
  osv: VulnSourceStatus;
}

/** Read the ingestion cursor for one source, or null if never run. */
export async function getSyncCursor(q: Queryable, source: VulnSyncSource): Promise<string | null> {
  const { rows } = await q.query<{ cursor: string | null }>(
    `SELECT cursor FROM vuln_sync_state WHERE source = $1`,
    [source],
  );
  return rows[0]?.cursor ?? null;
}

/**
 * Record a sync run. `cursor` is only advanced when non-null (a failed run passes
 * null to preserve the previous cursor while still marking last_ok=false).
 */
export async function setSyncState(
  q: Queryable,
  source: VulnSyncSource,
  cursor: string | null,
  ok: boolean,
): Promise<void> {
  await q.query(
    `INSERT INTO vuln_sync_state
       (source, cursor, last_run, last_ok, last_success_at, last_failure_at)
     VALUES ($1, $2, now(), $3,
       CASE WHEN $3 THEN now() ELSE NULL END,
       CASE WHEN NOT $3 THEN now() ELSE NULL END)
     ON CONFLICT (source) DO UPDATE SET
       cursor   = COALESCE(EXCLUDED.cursor, vuln_sync_state.cursor),
       last_run = now(),
       last_ok  = EXCLUDED.last_ok,
       last_success_at = CASE
         WHEN EXCLUDED.last_ok THEN now() ELSE vuln_sync_state.last_success_at END,
       last_failure_at = CASE
         WHEN NOT EXCLUDED.last_ok THEN now() ELSE vuln_sync_state.last_failure_at END`,
    [source, cursor, ok],
  );
}

export async function getAllSyncState(pool: Pool): Promise<VulnSyncStateRow[]> {
  const { rows } = await pool.query<VulnSyncStateRow>(
    `SELECT source, cursor, last_run, last_ok, last_success_at, last_failure_at
     FROM vuln_sync_state`,
  );
  return rows;
}

/** Data-freshness map for API responses (null per source until first sync). */
export async function getDataFreshness(pool: Pool): Promise<{
  nvd_last_sync: string | null;
  kev_last_sync: string | null;
  osv_last_sync: string | null;
}> {
  const rows = await getAllSyncState(pool);
  const bySource = new Map(rows.map((r) => [r.source, r.last_success_at]));
  return {
    nvd_last_sync: bySource.get("nvd-cve")?.toISOString() ?? null,
    kev_last_sync: bySource.get("kev")?.toISOString() ?? null,
    osv_last_sync: bySource.get("osv")?.toISOString() ?? null,
  };
}

/** Latest attempt outcome per source for health/admin operator visibility. */
export async function getVulnSyncStatus(pool: Pool): Promise<VulnSyncStatus> {
  const rows = await getAllSyncState(pool);
  const bySource = new Map(rows.map((row) => [row.source, row]));
  const status = (source: VulnSyncSource): VulnSourceStatus => {
    const row = bySource.get(source);
    return {
      last_attempt: row?.last_run?.toISOString() ?? null,
      last_success: row?.last_success_at?.toISOString() ?? null,
      last_failure: row?.last_failure_at?.toISOString() ?? null,
      last_ok: row?.last_ok ?? null,
    };
  };
  return { nvd: status("nvd-cve"), kev: status("kev"), osv: status("osv") };
}
