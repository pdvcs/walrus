import { Pool } from "pg";
import { getDataFreshness } from "../db/queries/vuln-sync-state.js";

export const BACKFILL_HINT =
  "No NVD vulnerability data yet — run `npm run vuln:backfill` (with NVD_API_KEY set) to " +
  "populate historical CVEs. The incremental `/internal/vuln-sync/nvd` trigger only covers " +
  "recently-modified CVEs, so on a fresh database it leaves most packages empty.";

/**
 * Operator-facing hints about vuln-data health. Currently: warn when NVD produced
 * zero affected-version rows (the tell-tale sign that only the incremental sync
 * has run and a one-time backfill is still needed). Surfaced in the /internal
 * and admin sync responses and the admin explorer's freshness panel.
 */
export async function getVulnHints(pool: Pool): Promise<string[]> {
  const hints: string[] = [];
  const { rows } = await pool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM cve_affects WHERE source = 'nvd'`,
  );
  const nvdAffects = rows[0]?.n ?? 0;
  if (nvdAffects === 0) {
    // Only nudge once at least one package declares CPE tracking (otherwise there
    // is legitimately nothing for NVD to populate).
    const { rows: cpe } = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM package_cpes`,
    );
    if ((cpe[0]?.n ?? 0) > 0) hints.push(BACKFILL_HINT);
  }
  return hints;
}

/** Convenience re-export so callers can show freshness alongside hints. */
export { getDataFreshness };
