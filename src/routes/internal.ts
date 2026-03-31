import { Router } from "express";
import { SyncRunResult } from "../services/sync-service.js";

export interface InternalRouteDeps {
  runSync: (
    packageName: string,
    opts: { dryRun: boolean; triggerType: "scheduled" },
  ) => Promise<SyncRunResult>;
  runSyncAll: (opts: {
    dryRun: boolean;
    triggerType: "scheduled";
  }) => Promise<Array<{ package: string; result: SyncRunResult }>>;
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

  return router;
}
