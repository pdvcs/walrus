import { Pool } from "pg";
import { listDistinctCpePairs } from "../db/queries/package-aliases.js";
import { getVulnBackfillJob, updateVulnBackfillJob } from "../db/queries/vuln-backfill-jobs.js";
import { hashCpePairs, markBackfillComplete } from "./vuln-backfill-autostart.js";
import { NvdClient } from "../vuln/sync/nvd-client.js";
import { backfillNvd, IngestCounts } from "../vuln/sync/nvd-sync.js";
import { withVulnSyncLock } from "../vuln/sync/lock.js";

export async function runVulnBackfillJob(
  pool: Pool,
  jobId: string,
  nvd = new NvdClient(),
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
