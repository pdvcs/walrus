import { Pool } from "pg";
import { log } from "../common/log.js";
import { listPackages } from "../db/queries/packages.js";
import { listVersions } from "../db/queries/versions.js";
import { listAffectsWithCveForPackage } from "../db/queries/cves.js";
import { findBlockingCve, VersionAvailabilityStatus } from "./vuln-service.js";

/**
 * Version-level availability history (WAL-36).
 *
 * The critical-CVE gate is a pure predicate evaluated on read, so there is no moment at
 * which a version "becomes" blocked — it simply starts answering differently. Transitions
 * are therefore detected by re-evaluating the gate after an ingestion run and comparing the
 * result against the last status recorded for each version.
 *
 * Doing it this way rather than at the point of the write has two consequences worth
 * keeping: it is source-agnostic for free — an `nvd` sync that ingests a fresh critical CVE
 * produces the same history as a `cvss` enrichment — and it measures what actually happened
 * rather than projecting what a change was expected to do.
 */

/** Ingestion labels a transition can be attributed to. Documentation of the expected
 * values rather than a constraint: the recorder stores whatever label the caller supplies,
 * because the routes have already validated the source they dispatched. */
export type TransitionSource = "nvd" | "kev" | "osv" | "cvss" | "all" | "backfill";
export type TransitionTrigger = "internal" | "admin";

export interface AvailabilityTransition {
  package_name: string;
  version: string;
  status: VersionAvailabilityStatus;
  cve_id: string | null;
  cvss_v3_score: string | null;
  severity: string | null;
  source: string;
  trigger_type: string;
  created_at: Date;
}

export interface RecordTransitionsResult {
  packagesChecked: number;
  versionsChecked: number;
  newlyBlocked: Array<{ package_name: string; version: string; cve_id: string | null }>;
  newlyAvailable: Array<{ package_name: string; version: string }>;
}

/** The most recent status recorded per version, for one package. */
async function lastRecordedStatuses(
  pool: Pool,
  packageName: string,
): Promise<Map<string, VersionAvailabilityStatus>> {
  const { rows } = await pool.query<{ version: string; status: VersionAvailabilityStatus }>(
    `SELECT DISTINCT ON (version) version, status
       FROM version_availability_events
      WHERE package_name = $1
      ORDER BY version, id DESC`,
    [packageName],
  );
  return new Map(rows.map((r) => [r.version, r.status]));
}

/**
 * Re-evaluate the gate for every cached version and record whatever changed.
 *
 * A version with no history yet is treated as previously `available`: only a *blocked*
 * first observation is worth a row. Recording "available" for every untouched version on
 * first run would write thousands of rows that say nothing happened.
 */
export async function recordAvailabilityTransitions(
  pool: Pool,
  attribution: { source: string; trigger: string },
): Promise<RecordTransitionsResult> {
  const result: RecordTransitionsResult = {
    packagesChecked: 0,
    versionsChecked: 0,
    newlyBlocked: [],
    newlyAvailable: [],
  };

  for (const pkg of await listPackages(pool)) {
    const [versions, affects] = await Promise.all([
      listVersions(pool, pkg.name, {}),
      listAffectsWithCveForPackage(pool, pkg.name),
    ]);
    if (versions.length === 0) continue;

    result.packagesChecked += 1;
    const previous = await lastRecordedStatuses(pool, pkg.name);

    for (const version of versions) {
      result.versionsChecked += 1;
      const blocking = findBlockingCve(version.version, affects);
      const status: VersionAvailabilityStatus = blocking === null ? "available" : "blocked";
      const before = previous.get(version.version) ?? "available";
      if (status === before) continue;

      await pool.query(
        `INSERT INTO version_availability_events
           (package_name, version, status, cve_id, cvss_v3_score, severity, source, trigger_type)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [
          pkg.name,
          version.version,
          status,
          blocking?.cve_id ?? null,
          blocking?.cvss_v3_score ?? null,
          blocking?.severity ?? null,
          attribution.source,
          attribution.trigger,
        ],
      );

      if (status === "blocked") {
        result.newlyBlocked.push({
          package_name: pkg.name,
          version: version.version,
          cve_id: blocking?.cve_id ?? null,
        });
      } else {
        result.newlyAvailable.push({ package_name: pkg.name, version: version.version });
      }
    }
  }

  if (result.newlyBlocked.length > 0 || result.newlyAvailable.length > 0) {
    log.info(
      {
        source: attribution.source,
        blocked: result.newlyBlocked.length,
        unblocked: result.newlyAvailable.length,
      },
      "Recorded version availability transitions",
    );
  }
  return result;
}

/** History for one version, newest first. */
export async function listAvailabilityHistory(
  pool: Pool,
  packageName: string,
  version: string,
  limit = 50,
): Promise<AvailabilityTransition[]> {
  const { rows } = await pool.query<AvailabilityTransition>(
    `SELECT package_name, version, status, cve_id, cvss_v3_score, severity,
            source, trigger_type, created_at
       FROM version_availability_events
      WHERE package_name = $1 AND version = $2
      ORDER BY id DESC
      LIMIT $3`,
    [packageName, version, limit],
  );
  return rows;
}

/** Recent transitions for a package, newest first — "what changed lately?". */
export async function listRecentTransitions(
  pool: Pool,
  packageName: string,
  limit = 100,
): Promise<AvailabilityTransition[]> {
  const { rows } = await pool.query<AvailabilityTransition>(
    `SELECT package_name, version, status, cve_id, cvss_v3_score, severity,
            source, trigger_type, created_at
       FROM version_availability_events
      WHERE package_name = $1
      ORDER BY id DESC
      LIMIT $2`,
    [packageName, limit],
  );
  return rows;
}
