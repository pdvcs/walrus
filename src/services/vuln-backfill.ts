import { Pool } from "pg";
import { listDistinctCpePairs } from "../db/queries/package-aliases.js";
import { getVulnBackfillJob, updateVulnBackfillJob } from "../db/queries/vuln-backfill-jobs.js";
import { hashCpePairs, markBackfillComplete } from "./vuln-backfill-autostart.js";
import { recordAvailabilityTransitions } from "./availability-history.js";
import { log } from "../common/log.js";
import { NvdClient } from "../vuln/sync/nvd-client.js";
import { backfillNvd, IngestCounts } from "../vuln/sync/nvd-sync.js";
import { withVulnSyncLock } from "../vuln/sync/lock.js";
import { osvSyncPackage } from "../vuln/sync/osv-sync.js";

export async function runVulnBackfillJob(
  pool: Pool,
  jobId: string,
  nvd = new NvdClient(),
  osvFetch?: typeof fetch,
): Promise<IngestCounts> {
  // Read the job first: its package_name decides which CPE pairs are in scope,
  // and therefore what cpe_pairs_total should report.
  const job = await getVulnBackfillJob(pool, jobId);
  const packageName = job?.package_name ?? undefined;
  const total = (await listDistinctCpePairs(pool, packageName)).length;
  await updateVulnBackfillJob(pool, jobId, {
    status: "running",
    started_at: new Date(),
    cpe_pairs_total: total,
  });
  try {
    const result = await withVulnSyncLock(pool, "nvd", () =>
      backfillNvd(pool, nvd, {
        since: job?.since_date ?? undefined,
        packageName,
        onPairComplete: (done) => updateVulnBackfillJob(pool, jobId, { cpe_pairs_done: done }),
      }),
    );
    if (packageName) {
      // WAL-54: the NVD walk alone leaves an OSV-primary package (requests) with a third of its
      // advisories until the weekly cross-check, so the targeted run covers OSV too. Best-effort:
      // an OSV outage must not fail the NVD backfill that already succeeded, and the package is
      // not reported as covered (osv_synced_at stays null) until OSV is actually read.
      await osvSyncPackage(pool, packageName, osvFetch).catch((err: unknown) =>
        log.warn({ err, package: packageName }, "Targeted OSV sync failed; weekly sync will retry"),
      );
    }
    await updateVulnBackfillJob(pool, jobId, { status: "succeeded", finished_at: new Date() });
    if (packageName) {
      // Record which CPE set this run covered, so the autostart sweep stops selecting the
      // package — and selects it again if a pair is later added. Computed now rather than at
      // launch: the set is whatever was actually walked.
      await markBackfillComplete(
        pool,
        packageName,
        hashCpePairs(await listDistinctCpePairs(pool, packageName)),
      );
    }
    // A backfill ingests historical CVEs, so it blocks versions as readily as any sync.
    await recordAvailabilityTransitions(pool, { source: "backfill", trigger: "internal" }).catch(
      (err: unknown) => log.error({ err }, "Failed to record availability transitions"),
    );
    return result;
  } catch (error) {
    await updateVulnBackfillJob(pool, jobId, {
      status: "failed",
      finished_at: new Date(),
      error_message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}
