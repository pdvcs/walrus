import { Router } from "express";
import { SyncRunResult } from "../services/sync-service.js";
import { isVulnSyncSource, runVulnSync, VulnSyncImpls } from "../vuln/sync/index.js";
import { buildPublicationWindows } from "../vuln/sync/nvd-sync.js";
import type { VulnBackfillJobRow } from "../db/queries/vuln-backfill-jobs.js";

export interface InternalRouteDeps {
  runSync: (
    packageName: string,
    opts: { dryRun: boolean; triggerType: "scheduled" },
  ) => Promise<SyncRunResult>;
  runSyncAll: (opts: {
    dryRun: boolean;
    triggerType: "scheduled";
  }) => Promise<Array<{ package: string; result: SyncRunResult }>>;
  /** Vuln sync implementations, injected from main.ts (real NVD/KEV/OSV) or tests (fakes). */
  vulnSync: VulnSyncImpls;
  /** Operator hints (e.g. "run vuln:backfill"); appended to the sync response when non-empty. */
  vulnHints?: () => Promise<string[]>;
  startVulnBackfill?: (
    since?: string,
  ) => Promise<{ job?: VulnBackfillJobRow; alreadyRunning?: boolean }>;
  getVulnBackfill?: (id: string) => Promise<VulnBackfillJobRow | null>;
}

export function createInternalRouter(deps: InternalRouteDeps): Router {
  const router = Router();

  router.post("/sync", async (req, res, next) => {
    try {
      const body = (req.body ?? {}) as { package?: unknown; dry_run?: unknown };
      const packageName =
        typeof body.package === "string" && body.package.length > 0 ? body.package : undefined;
      const dryRun = body.dry_run === true;

      if (packageName) {
        const result = await deps.runSync(packageName, { dryRun, triggerType: "scheduled" });
        res.status(202).json({ package: packageName, dry_run: dryRun, result });
        return;
      }

      const results = await deps.runSyncAll({ dryRun, triggerType: "scheduled" });
      res.status(202).json({ dry_run: dryRun, results });
    } catch (err) {
      next(err);
    }
  });

  // Vuln ingestion triggers (external cron). source ∈ nvd | kev | osv | all.
  // Suggested cadence: NVD 2-hourly, KEV daily, OSV weekly (see build-release.md).
  router.post("/vuln-sync/:source", async (req, res, next) => {
    try {
      const source = req.params.source;
      if (!isVulnSyncSource(source)) {
        res.status(400).json({ error: `Unknown vuln sync source: ${source}` });
        return;
      }
      const outcomes = await runVulnSync(source, deps.vulnSync);
      const allOk = outcomes.every((o) => o.ok);
      const alreadyRunning = source !== "all" && outcomes[0]?.code === "already_running";
      const hints = deps.vulnHints ? await deps.vulnHints() : [];
      res.status(allOk ? 200 : alreadyRunning ? 409 : 207).json({
        source,
        outcomes,
        ...(hints.length > 0 ? { hints } : {}),
      });
    } catch (err) {
      next(err);
    }
  });

  router.post("/vuln-backfill", async (req, res, next) => {
    try {
      if (!deps.startVulnBackfill)
        return void res.status(503).json({ error: "Backfill launcher unavailable" });
      const body = (req.body ?? {}) as { since?: unknown };
      const since = typeof body.since === "string" ? body.since : undefined;
      if (body.since !== undefined && !since)
        return void res.status(400).json({ error: "since must be a YYYY-MM-DD string" });
      try {
        if (since) buildPublicationWindows(since);
      } catch (error) {
        return void res
          .status(400)
          .json({ error: error instanceof Error ? error.message : String(error) });
      }
      const result = await deps.startVulnBackfill(since);
      if (result.alreadyRunning)
        return void res.status(409).json({
          code: "already_running",
          ...(result.job ? { job: serializeJob(result.job) } : {}),
        });
      if (!result.job) throw new Error("Backfill launcher did not return a job");
      res.status(202).json({
        job: serializeJob(result.job),
        status_url: `/internal/vuln-backfill/${result.job.id}`,
      });
    } catch (err) {
      next(err);
    }
  });

  router.get("/vuln-backfill/:id", async (req, res, next) => {
    try {
      if (!deps.getVulnBackfill)
        return void res.status(503).json({ error: "Backfill status unavailable" });
      const job = await deps.getVulnBackfill(req.params.id);
      if (!job) return void res.status(404).json({ error: "Backfill job not found" });
      res.json({ job: serializeJob(job) });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function serializeJob(job: VulnBackfillJobRow) {
  return {
    ...job,
    started_at: job.started_at?.toISOString() ?? null,
    finished_at: job.finished_at?.toISOString() ?? null,
    created_at: job.created_at.toISOString(),
  };
}
