import { Router } from "express";
import { SyncRunResult } from "../services/sync-service.js";
import { isVulnSyncSource, runVulnSync, VulnSyncImpls } from "../vuln/sync/index.js";

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
      const hints = deps.vulnHints ? await deps.vulnHints() : [];
      res.status(allOk ? 200 : 207).json({
        source,
        outcomes,
        ...(hints.length > 0 ? { hints } : {}),
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
