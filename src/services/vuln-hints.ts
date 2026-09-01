import { Pool } from "pg";
import { getDataFreshness } from "../db/queries/vuln-sync-state.js";
import { MAX_ATTEMPTS } from "./vuln-backfill-autostart.js";

/**
 * Operator-facing hints about vuln-data health.
 *
 * These are *reports*, not instructions. Walrus closes its own CVE-coverage gaps
 * (ADR-003): a package whose CPE set has never been backfilled is picked up by the
 * autostart sweep. A hint appears only when that self-healing has stopped working —
 * the sweep is switched off, or a package has exhausted its retries — because those
 * are the cases a human genuinely has to look at.
 *
 * The old hint told operators to run `npm run vuln:backfill`, which production cannot
 * do: the image installs no dev dependencies and never copies `scripts/`. It also
 * fired only when `cve_affects` was globally empty, so it never fired at all for a
 * package added after the first backfill — exactly the case that needed attention.
 */
export function backfillDisabledHint(packages: string[]): string {
  return (
    `${packages.length} package(s) have no NVD CVE history and autonomous backfill is ` +
    `disabled (VULN_AUTO_BACKFILL=false): ${packages.join(", ")}. Their versions are served ` +
    `without CVE data ever having been ingested. Re-enable it, or POST ` +
    `/internal/vuln-backfill with {"package":"<name>"} for each.`
  );
}

/**
 * WAL-100 AC2. The hint used to end at "no longer being retried", which tells an operator the
 * state and not the move — the same gap WAL-43 AC6 closed for alerts. It now names the route that
 * clears the budget, because the alternative recovery was a psql session against a database the
 * deployment deliberately keeps off the public internet.
 */
export function backfillStuckHint(entries: Array<{ name: string; error: string | null }>): string {
  const detail = entries.map((e) => `${e.name}${e.error ? ` (${e.error})` : ""}`).join("; ");
  return (
    `${entries.length} package(s) have exhausted ${MAX_ATTEMPTS} automatic CVE backfill ` +
    `attempts and are no longer being retried: ${detail}. Until this is resolved their ` +
    `versions are served without complete CVE data. Fix the underlying cause first — the ` +
    `error above is why the launch failed — then POST /admin/v1/vuln-backfill/reset-attempts ` +
    `to make them eligible for the next sweep, optionally with {"package":"<name>"} for one.`
  );
}

export async function getVulnHints(
  pool: Pool,
  opts: { autoBackfillEnabled?: boolean } = {},
): Promise<string[]> {
  const autoEnabled = opts.autoBackfillEnabled ?? true;
  const hints: string[] = [];

  // Per package, not global. The previous global check went quiet permanently after the
  // first backfill, which is precisely when new packages start being missed.
  const { rows } = await pool.query<{
    name: string;
    attempts: number;
    last_error: string | null;
  }>(
    `SELECT p.name, p.vuln_backfill_attempts AS attempts, p.vuln_backfill_last_error AS last_error
       FROM packages p
      WHERE p.vuln_backfill_completed_at IS NULL
        AND EXISTS (SELECT 1 FROM package_cpes c WHERE c.package_name = p.name)
      ORDER BY p.name`,
  );
  if (rows.length === 0) return hints;

  const stuck = rows.filter((r) => r.attempts >= MAX_ATTEMPTS);
  if (stuck.length > 0) {
    hints.push(backfillStuckHint(stuck.map((r) => ({ name: r.name, error: r.last_error }))));
  }

  const waiting = rows.filter((r) => r.attempts < MAX_ATTEMPTS);
  if (!autoEnabled && waiting.length > 0) {
    hints.push(backfillDisabledHint(waiting.map((r) => r.name)));
  }

  return hints;
}

/** Convenience re-export so callers can show freshness alongside hints. */
export { getDataFreshness };
