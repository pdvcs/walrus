import { Pool } from "pg";
import {
  getVulnSyncStatus,
  VulnSourceStatus,
  VulnSyncStatus,
} from "../db/queries/vuln-sync-state.js";
import { getVulnHints } from "./vuln-hints.js";
import { countActiveCveSuppressions } from "../db/queries/cve-suppressions.js";

/**
 * Degradation reporting (PO decision 2026-08-26).
 *
 * Walrus's vulnerability ingestion is autonomous (ADR-003), which means it can also stop
 * working autonomously — a deleted scheduler job, IAM drift, an upstream outage — with no
 * failing request to alert anyone. This module answers "is any part of the self-healing
 * machinery not doing its job?" so that /app/status and the admin homepage can show it.
 *
 * Degradations deliberately do not make the application unavailable: availability is reserved
 * for failures that stop the application serving at all, while a degradation means walrus is
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
 * Generous multiples of the scheduled cadence (nvd 2-hourly, kev daily, osv weekly,
 * cvss daily — infra/terraform/scheduler.tf), so a single failed or contended run never
 * trips them; only a pattern of failure, or a scheduler that has stopped firing, does.
 * cvss runs are idempotent and deadline-bounded like nvd, but at kev-like daily cadence —
 * and it is the one trigger that can newly block downloads, so it gets no extra slack
 * beyond what a missed-run pattern already allows.
 */
export const STALENESS_THRESHOLDS_MS = {
  nvd: 12 * 3600 * 1000, // ~6 missed 2-hourly runs
  kev: 48 * 3600 * 1000, // 2 missed daily runs
  osv: 8 * 24 * 3600 * 1000, // a missed weekly run plus a day
  cvss: 48 * 3600 * 1000, // 2 missed daily runs
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
    // Never succeeded. A first attempt still in flight (start marker written, no outcome
    // yet, nothing failed) has not had its chance — degrade only once that marker ages
    // past the threshold, mirroring the generosity applied to established sources.
    if (status.last_attempt && status.last_ok === null && !status.last_failure) {
      const age = now.getTime() - new Date(status.last_attempt).getTime();
      if (age <= threshold) return null;
      return {
        component,
        reason:
          `${source} ingestion started ${fmtAgeHours(age)} ago and has never completed ` +
          `successfully — the run may be stuck or repeatedly cut off. Vulnerability data ` +
          `from this source is missing entirely.`,
      };
    }
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
  for (const source of ["nvd", "kev", "osv", "cvss"] as const) {
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
 * there would train operators to ignore the banner. The gate is per source — NVD matters
 * once any CPE pair exists, OSV once any package has an OSV mapping, KEV and cvss once
 * either path can produce CVEs worth scoring or flagging.
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
      "vuln-sync-cvss": hasCpes || hasOsv, // enrichment candidates arise from either path
    };
    const all = computeSyncDegradations(await getVulnSyncStatus(pool), now);
    degradations.push(...all.filter((d) => relevant[d.component]));
  }

  const hints = await getVulnHints(pool, { autoBackfillEnabled: opts.autoBackfillEnabled });
  for (const hint of hints) {
    degradations.push({ component: "vuln-backfill", reason: hint });
  }

  const activeSuppressions = await countActiveCveSuppressions(pool);
  if (activeSuppressions > 0) {
    degradations.push({
      component: "cve-suppressions",
      reason: `${activeSuppressions} operator CVE suppression${activeSuppressions === 1 ? "" : "s"} active; review the list regularly for a missing general rule or an assertion that can be retired.`,
    });
  }

  return degradations;
}
