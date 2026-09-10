import { Pool } from "pg";
import { getActiveCveSuppressionSummary } from "../db/queries/cve-suppressions.js";
import { getVulnSyncStatus, type VulnSyncStatus } from "../db/queries/vuln-sync-state.js";
import { getDegradations, type Degradation } from "./degradations.js";

export interface PackageMetricRow {
  state: "enabled" | "disabled" | "removed";
  count: number;
}

export interface ArtifactMetricRow {
  package_name: string;
  status: "pending" | "cooling_off" | "downloading" | "available" | "failed" | "removed";
  count: number;
  stored_bytes: number;
  oldest_at: Date | null;
}

export interface PackageSyncMetricRow {
  package_name: string;
  running: number;
  last_attempt: Date;
  last_success: Date | null;
  last_failure: Date | null;
  latest_status: "running" | "completed" | "failed";
  latest_trigger: "scheduled" | "on-demand" | "admin" | "historical-backfill";
  latest_started_at: Date;
  latest_completed_at: Date | null;
  artifacts_queued: number;
  artifacts_downloaded: number;
  artifacts_failed: number;
}

export interface CountByStatusRow {
  status: string;
  count: number;
}

export interface BlockedVersionMetricRow {
  package_name: string;
  count: number;
}

export interface MetricsSnapshot {
  packages: PackageMetricRow[];
  artifacts: ArtifactMetricRow[];
  packageSyncs: PackageSyncMetricRow[];
  vulnSync: VulnSyncStatus;
  degradations: Degradation[];
  vulnerabilityEnrichmentBacklog: number;
  vulnerabilityBackfills: CountByStatusRow[];
  blockedVersions: BlockedVersionMetricRow[];
  activeSuppressions: number;
  nextSuppressionExpiry: string | null;
}

export async function getMetricsSnapshot(
  pool: Pool,
  opts: { autoBackfillEnabled?: boolean } = {},
): Promise<MetricsSnapshot> {
  const query = <T extends object>(text: string) => pool.query<T>(text);

  const [
    packageResult,
    artifactResult,
    syncResult,
    vulnSync,
    degradations,
    backlogResult,
    backfillResult,
    blockedResult,
    suppression,
  ] = await Promise.all([
    query<PackageMetricRow>(
      `SELECT CASE
                WHEN removed_at IS NOT NULL THEN 'removed'
                WHEN enabled THEN 'enabled'
                ELSE 'disabled'
              END AS state,
              count(*)::int AS count
         FROM packages
        GROUP BY state`,
    ),
    query<ArtifactMetricRow>(
      `WITH classified AS (
         SELECT v.package_name,
                CASE
                  WHEN a.status = 'pending' AND a.cooling_off_until > now() THEN 'cooling_off'
                  ELSE a.status
                END AS status,
                a.file_size,
                a.created_at
           FROM artifacts a
           JOIN versions v ON v.id = a.version_id
       )
       SELECT package_name, status, count(*)::int AS count,
              coalesce(sum(file_size) FILTER (WHERE status = 'available'), 0)::float8
                AS stored_bytes,
              min(created_at) FILTER (WHERE status IN ('pending', 'downloading', 'failed'))
                AS oldest_at
         FROM classified
        GROUP BY package_name, status`,
    ),
    query<PackageSyncMetricRow>(
      `WITH stats AS (
         SELECT package_name,
                count(*) FILTER (WHERE status = 'running')::int AS running,
                max(started_at) AS last_attempt,
                max(completed_at) FILTER (WHERE status = 'completed') AS last_success,
                max(completed_at) FILTER (WHERE status = 'failed') AS last_failure
           FROM sync_jobs
          GROUP BY package_name
       ), latest AS (
         SELECT DISTINCT ON (package_name)
                package_name, status, trigger_type, started_at, completed_at,
                artifacts_queued, artifacts_downloaded, artifacts_failed
           FROM sync_jobs
          ORDER BY package_name, started_at DESC, id DESC
       )
       SELECT s.package_name, s.running, s.last_attempt, s.last_success, s.last_failure,
              l.status AS latest_status, l.trigger_type AS latest_trigger,
              l.started_at AS latest_started_at, l.completed_at AS latest_completed_at,
              l.artifacts_queued, l.artifacts_downloaded, l.artifacts_failed
         FROM stats s
         JOIN latest l USING (package_name)`,
    ),
    getVulnSyncStatus(pool),
    getDegradations(pool, { autoBackfillEnabled: opts.autoBackfillEnabled }),
    query<{ count: number }>(
      `SELECT count(*)::int AS count
         FROM cves
        WHERE severity IS NULL AND severity_source IS NULL`,
    ),
    query<CountByStatusRow>(
      `SELECT status, count(*)::int AS count
         FROM vuln_backfill_jobs
        WHERE status IN ('queued', 'running')
        GROUP BY status`,
    ),
    query<BlockedVersionMetricRow>(
      `WITH latest AS (
         SELECT DISTINCT ON (package_name, version) package_name, version, status
           FROM version_availability_events
          ORDER BY package_name, version, id DESC
       )
       SELECT package_name, count(*)::int AS count
         FROM latest l
         JOIN versions v USING (package_name, version)
         JOIN packages p ON p.name = l.package_name
        WHERE l.status = 'blocked'
          AND p.enabled
          AND p.removed_at IS NULL
        GROUP BY package_name`,
    ),
    getActiveCveSuppressionSummary(pool),
  ]);

  return {
    packages: packageResult.rows,
    artifacts: artifactResult.rows,
    packageSyncs: syncResult.rows,
    vulnSync,
    degradations,
    vulnerabilityEnrichmentBacklog: backlogResult.rows[0]?.count ?? 0,
    vulnerabilityBackfills: backfillResult.rows,
    blockedVersions: blockedResult.rows,
    activeSuppressions: suppression.active_count,
    nextSuppressionExpiry: suppression.next_expiry,
  };
}
