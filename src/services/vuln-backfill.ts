import { Pool } from "pg";
import { listDistinctCpePairs } from "../db/queries/package-aliases.js";
import { updateVulnBackfillJob } from "../db/queries/vuln-backfill-jobs.js";
import { NvdClient } from "../vuln/sync/nvd-client.js";
import { backfillNvd, IngestCounts } from "../vuln/sync/nvd-sync.js";
import { withVulnSyncLock } from "../vuln/sync/lock.js";

export async function runVulnBackfillJob(
  pool: Pool,
  jobId: string,
  nvd = new NvdClient(),
): Promise<IngestCounts> {
  const total = (await listDistinctCpePairs(pool)).length;
  await updateVulnBackfillJob(pool, jobId, {
    status: "running",
    started_at: new Date(),
    cpe_pairs_total: total,
  });
  try {
    const job = await import("../db/queries/vuln-backfill-jobs.js").then((m) =>
      m.getVulnBackfillJob(pool, jobId),
    );
    const result = await withVulnSyncLock(pool, "nvd", () =>
      backfillNvd(pool, nvd, {
        since: job?.since_date ?? undefined,
        onPairComplete: (done) => updateVulnBackfillJob(pool, jobId, { cpe_pairs_done: done }),
      }),
    );
    await updateVulnBackfillJob(pool, jobId, { status: "succeeded", finished_at: new Date() });
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
