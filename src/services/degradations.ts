import { Pool } from "pg";
import { getVulnSyncStatus, VulnSourceStatus, VulnSyncStatus } from "../db/queries/vuln-sync-state.js";
import { getVulnHints } from "./vuln-hints.js";

/**
 * Degradation reporting (PO decision 2026-08-26).
 *
 * Walrus's vulnerability ingestion is autonomous (ADR-003), which means it can also stop
 * working autonomously — a deleted scheduler job, IAM drift, an upstream outage — with no
 * failing request to alert anyone. This module answers "is any part of the self-healing
 * machinery not doing its job?" so that /health and the admin homepage can show it.
 *
 * Degradations deliberately do NOT flip /health's `status` away from "ok": status is
 * reserved for major events (the process cannot serve), while a degradation means walrus is
 * serving but some data is going stale or some gap is not being closed. Alerting and email
 * notification are planned on top of this; until then the admin homepage banner is the
 * surface an operator sees.
 */

export interface Degradation {
  /** What is degraded: `vuln-sync-nvd` | `vuln-sync-kev` | `vuln-sync-osv` | `vuln-backfill`. */
  component: string;
  reason: string;
}

/**
 * How stale each source's last *successful* run may be before it is degraded.
 *
 * Generous multiples of the scheduled cadence (nvd 2-hourly, kev daily, osv weekly —
 * infra/terraform/scheduler.tf), so a single failed or contended run never trips them;
 * only a pattern of failure, or a scheduler that has stopped firing, does.
 */
export const STALENESS_THRESHOLDS_MS = {
  nvd: 12 * 3600 * 1000, // ~6 missed 2-hourly runs
  kev: 48 * 3600 * 1000, // 2 missed daily runs
  osv: 8 * 24 * 3600 * 1000, // a missed weekly run plus a day
} as const;

type StalenessSource = keyof typeof STALENESS_THRESHOLDS_MS;

function fmtAgeHours(ms: number): string {
  const hours = ms / 3_600_000;
  return hours < 48 ? `${Math.floor(hours)}h` : `${Math.floor(hours / 24)}d`;
}

function sourceDegradation(
  source: StalenessSource,
  status: VulnSourceStatus,
  now: Date,
): Degradation | null {
  const component = `vuln-sync-${source}`;
  const threshold = STALENESS_THRESHOLDS_MS[source];

  if (!status.last_success) {
    return {
      component,
      reason:
        `${source} ingestion has never completed successfully` +
        (status.last_attempt ? ` (last attempt ${status.last_attempt})` : " (never attempted)") +
        `; vulnerability data from this source is missing entirely.`,
    };
  }

  const age = now.getTime() - new Date(status.last_success).getTime();
  if (age > threshold) {
    return {
      component,
      reason:
        `${source} ingestion last succeeded ${fmtAgeHours(age)} ago ` +
        `(threshold ${fmtAgeHours(threshold)})` +
        (status.last_ok === false && status.last_failure
          ? `; latest attempt failed at ${status.last_failure}`
          : "") +
        `. Vulnerability data from this source is going stale.`,
    };
  }

  if (status.last_ok === false) {
    return {
      component,
      reason:
        `latest ${source} sync attempt failed` +
        (status.last_failure ? ` at ${status.last_failure}` : "") +
        ` (last success ${status.last_success}); the scheduler should retry, ` +
        `but a repeat becomes staleness.`,
    };
  }

  return null;
}

/**
 * Staleness/failure degradations from sync state alone. Pure — injected status and clock —
 * so the thresholds are unit-testable without a database.
 */
export function computeSyncDegradations(status: VulnSyncStatus, now: Date): Degradation[] {
  const out: Degradation[] = [];
  for (const source of ["nvd", "kev", "osv"] as const) {
    const d = sourceDegradation(source, status[source], now);
    if (d) out.push(d);
  }
  return out;
}

/**
 * All current degradations: sync staleness plus the operator hints (stuck or disabled
 * backfills — the cases where self-healing has stopped, see vuln-hints.ts).
 *
 * Sync staleness is only meaningful when something is actually tracked: a deployment with
 * no `[vulnerabilities]` sections has nothing to ingest, and reporting "NVD never synced"
 * there would train operators to ignore the banner. The gate is per source — NVD and KEV
 * matter once any CPE pair exists, OSV once any package has an OSV mapping.
 */
export async function getDegradations(
  pool: Pool,
  opts: { autoBackfillEnabled?: boolean; now?: Date } = {},
): Promise<Degradation[]> {
  const now = opts.now ?? new Date();
  const degradations: Degradation[] = [];

  const { rows } = await pool.query<{ has_cpes: boolean; has_osv: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM package_cpes) AS has_cpes,
            EXISTS (SELECT 1 FROM packages WHERE osv_ecosystem IS NOT NULL) AS has_osv`,
  );
  const hasCpes = rows[0]?.has_cpes ?? false;
  const hasOsv = rows[0]?.has_osv ?? false;
  if (hasCpes || hasOsv) {
    const relevant: Record<string, boolean> = {
      "vuln-sync-nvd": hasCpes,
      "vuln-sync-kev": hasCpes || hasOsv, // KEV flags CVE rows from either path
      "vuln-sync-osv": hasOsv,
    };
    const all = computeSyncDegradations(await getVulnSyncStatus(pool), now);
    degradations.push(...all.filter((d) => relevant[d.component]));
  }

  const hints = await getVulnHints(pool, { autoBackfillEnabled: opts.autoBackfillEnabled });
  for (const hint of hints) {
    degradations.push({ component: "vuln-backfill", reason: hint });
  }

  return degradations;
}
