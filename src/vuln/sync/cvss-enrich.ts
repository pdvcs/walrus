/**
 * CVSS enrichment pass.
 *
 * Most CVEs without a severity are OSV stubs: `upsertCveStub` never sets one,
 * and the CPE-keyed NVD paths cannot reach them because those CVEs sit in NVD
 * with `vulnStatus: "Deferred"` — full CVSS metrics, but no CPE configurations,
 * so a `virtualMatchString` query never returns them. A by-id lookup does.
 *
 * This walks `cves WHERE severity IS NULL`, fetches each from NVD by id, and
 * re-upserts through the shared `extractCvss` + `upsertCveFull` path, so it
 * picks up the CVSS v2 fallback for free. CVEs NVD has rejected or never scored
 * stay NULL, which is correct.
 */
import { Pool } from "pg";
import { NvdClient } from "./nvd-client.js";
import { extractCvss } from "./nvd-sync.js";
import {
  listCveIdsMissingSeverity,
  updateCveCvss,
  markCveSeverityUnavailable,
  listAffectsWithCveForPackage,
  AffectsWithCveRow,
} from "../../db/queries/cves.js";
import { listVersions } from "../../db/queries/versions.js";
import { listPackages } from "../../db/queries/packages.js";
import { setSyncState } from "../../db/queries/vuln-sync-state.js";
import { getVersionAvailabilityStatus, meetsCriticalGate } from "../../services/vuln-service.js";

type Logger = (msg: string) => void;

/** What enrichment would set on one CVE. */
export interface CvssProposal {
  cve_id: string;
  severity: string;
  severity_source: string;
  cvss_v3_score: number | null;
  cvss_v4_score: number | null;
  cvss_v2_score: number | null;
  /** True when this would newly satisfy the >= 9.0 download gate. */
  crosses_critical_gate: boolean;
}

export interface CvssEnrichResult extends Record<string, unknown> {
  candidates: number;
  fetched: number;
  /** Rows written (0 when dryRun). */
  updated: number;
  /** NVD returned nothing for the id. */
  not_found: number;
  /** NVD had the CVE but no usable CVSS (Rejected / never scored). */
  no_metrics: number;
  /** Fetches that errored; these stay candidates for the next run. */
  errors: number;
  proposals: CvssProposal[];
}

/**
 * Fetch missing-severity CVEs from NVD and apply (or, with `dryRun`, only
 * report) their CVSS. Failures on a single CVE are counted and skipped rather
 * than aborting the walk — one bad id should not strand the rest.
 *
 * Real runs record their lifecycle in vuln_sync_state (start marker → success,
 * or failure on throw) so staleness degradations and /app/status can see this
 * source like any other; it is the one scheduled trigger that can newly block
 * downloads. A dry run writes nothing anywhere — that is its contract.
 */
export async function enrichMissingCvss(
  pool: Pool,
  nvd: NvdClient,
  opts: { dryRun?: boolean; limit?: number; log?: Logger } = {},
): Promise<CvssEnrichResult> {
  const log = opts.log ?? (() => {});
  const ids = await listCveIdsMissingSeverity(pool, opts.limit);
  const result: CvssEnrichResult = {
    candidates: ids.length,
    fetched: 0,
    updated: 0,
    not_found: 0,
    no_metrics: 0,
    errors: 0,
    proposals: [],
  };
  log(`cvss-enrich: ${ids.length} CVE(s) with no severity${opts.dryRun ? " (dry run)" : ""}`);
  // `null` marks an attempt begun without an outcome yet — see setSyncState.
  if (!opts.dryRun) await setSyncState(pool, "cvss", null, null);

  try {
    await walkMissingSeverity(pool, nvd, ids, result, opts, log);
  } catch (err) {
    if (!opts.dryRun) await setSyncState(pool, "cvss", null, false);
    throw err;
  }
  if (!opts.dryRun) await setSyncState(pool, "cvss", null, true);

  log(
    `cvss-enrich: fetched ${result.fetched}, ${opts.dryRun ? "would update" : "updated"} ` +
      `${opts.dryRun ? result.proposals.length : result.updated}, ` +
      `${result.not_found} not in NVD, ${result.no_metrics} without CVSS, ${result.errors} errored`,
  );
  return result;
}

/**
 * The per-CVE walk itself, shared by real runs and dry-run previews. Counts and
 * applies into `result`. Per-CVE fetch failures are counted and skipped, so only
 * a systemic failure (a broken pool, a dead client) escapes to the caller.
 */
async function walkMissingSeverity(
  pool: Pool,
  nvd: NvdClient,
  ids: string[],
  result: CvssEnrichResult,
  opts: { dryRun?: boolean },
  log: Logger,
): Promise<void> {
  for (const id of ids) {
    let item;
    try {
      item = await nvd.cveById(id);
    } catch (err) {
      // A transient failure must stay a candidate, so no sentinel is written.
      result.errors++;
      log(`  ${id}: fetch failed — ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    if (!item) {
      result.not_found++;
      if (!opts.dryRun) await markCveSeverityUnavailable(pool, id, "nvd-not-found");
      continue;
    }
    result.fetched++;

    const cvss = extractCvss(item);
    if (!cvss.severity || !cvss.severitySource) {
      // Rejected or never scored upstream — terminal, so record it and stop
      // reconsidering this CVE on every future run.
      result.no_metrics++;
      if (!opts.dryRun) await markCveSeverityUnavailable(pool, id, "nvd-no-metrics");
      continue;
    }

    result.proposals.push({
      cve_id: id,
      severity: cvss.severity,
      severity_source: cvss.severitySource,
      cvss_v3_score: cvss.score,
      cvss_v4_score: cvss.v4Score,
      cvss_v2_score: cvss.v2Score,
      // The gate predicate itself, so the preview cannot drift from what the
      // download route will actually enforce once the proposal is applied.
      crosses_critical_gate: meetsCriticalGate({
        cvss_v3_score: cvss.score,
        cvss_v4_score: cvss.v4Score,
        cvss_v2_score: cvss.v2Score,
        severity: cvss.severity,
      }),
    });

    if (opts.dryRun) continue;

    await updateCveCvss(pool, {
      id,
      cvss_v3_score: cvss.score,
      cvss_v3_vector: cvss.vector,
      cvss_v4_score: cvss.v4Score,
      cvss_v4_vector: cvss.v4Vector,
      cvss_v2_score: cvss.v2Score,
      cvss_v2_vector: cvss.v2Vector,
      severity: cvss.severity,
      severity_source: cvss.severitySource,
    });
    result.updated++;
  }
}

export interface GateDelta {
  package_name: string;
  newly_blocked: string[];
}

/**
 * Which versions would newly fail the download gate if `proposals` were applied.
 *
 * Deliberately reuses `getVersionAvailabilityStatus` rather than re-deriving the
 * predicate: run it over the current affects rows, then again over the same rows
 * with proposed scores patched in, and diff. Read-only — call before applying.
 */
export async function previewGateDelta(
  pool: Pool,
  proposals: CvssProposal[],
): Promise<GateDelta[]> {
  const byCve = new Map(proposals.map((p) => [p.cve_id, p]));
  if (byCve.size === 0) return [];

  const deltas: GateDelta[] = [];
  for (const pkg of await listPackages(pool)) {
    const affects = await listAffectsWithCveForPackage(pool, pkg.name);
    if (!affects.some((row) => byCve.has(row.cve_id))) continue;

    const patched: AffectsWithCveRow[] = affects.map((row) => {
      const p = byCve.get(row.cve_id);
      if (!p) return row;
      return {
        ...row,
        severity: p.severity,
        severity_source: p.severity_source,
        cvss_v3_score: p.cvss_v3_score === null ? null : String(p.cvss_v3_score),
        cvss_v4_score: p.cvss_v4_score === null ? null : String(p.cvss_v4_score),
        cvss_v2_score: p.cvss_v2_score === null ? null : String(p.cvss_v2_score),
      };
    });

    const newly: string[] = [];
    for (const v of await listVersions(pool, pkg.name, {})) {
      const before = getVersionAvailabilityStatus(v.version, affects);
      const after = getVersionAvailabilityStatus(v.version, patched);
      if (before !== "blocked" && after === "blocked") newly.push(v.version);
    }
    if (newly.length > 0) deltas.push({ package_name: pkg.name, newly_blocked: newly });
  }
  return deltas;
}
