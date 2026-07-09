import { Pool } from "pg";
import { Queryable } from "../queryable.js";

export type VulnSyncSource = "nvd-cve" | "kev" | "osv";

export interface VulnSyncStateRow {
  source: string;
  cursor: string | null;
  last_run: Date | null;
  last_ok: boolean | null;
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
    `INSERT INTO vuln_sync_state (source, cursor, last_run, last_ok) VALUES ($1, $2, now(), $3)
     ON CONFLICT (source) DO UPDATE SET
       cursor   = COALESCE(EXCLUDED.cursor, vuln_sync_state.cursor),
       last_run = now(),
       last_ok  = EXCLUDED.last_ok`,
    [source, cursor, ok],
  );
}

export async function getAllSyncState(pool: Pool): Promise<VulnSyncStateRow[]> {
  const { rows } = await pool.query<VulnSyncStateRow>(
    `SELECT source, cursor, last_run, last_ok FROM vuln_sync_state`,
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
  const bySource = new Map(rows.map((r) => [r.source, r.last_run]));
  return {
    nvd_last_sync: bySource.get("nvd-cve")?.toISOString() ?? null,
    kev_last_sync: bySource.get("kev")?.toISOString() ?? null,
    osv_last_sync: bySource.get("osv")?.toISOString() ?? null,
  };
}
