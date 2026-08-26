import { Router } from "express";
import { SyncAlreadyRunningError, SyncRunResult } from "../services/sync-service.js";
import {
  isVulnSyncSource,
  parseVulnSyncOptions,
  runVulnSync,
  VulnSyncImpls,
} from "../vuln/sync/index.js";
import { VulnSyncAlreadyRunningError } from "../vuln/sync/lock.js";
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
  }) => Promise<Array<{ package: string; result?: SyncRunResult; skipped?: string }>>;
  /** Vuln sync implementations, injected from main.ts (real NVD/KEV/OSV) or tests (fakes). */
  vulnSync: VulnSyncImpls;
  /** Operator hints (e.g. "run vuln:backfill"); appended to the sync response when non-empty. */
  vulnHints?: () => Promise<string[]>;
  /**
   * Audit sink for vuln-sync triggers. These runs are machine-driven — `cvss` is on a
   * schedule and can newly block downloads (ADR-002) — so the trail must record them the
   * same way it records an operator clicking "Sync now", or an unattended gate change
   * leaves no evidence of when it happened.
   */
  logAdminAction?: (details: Record<string, unknown>) => Promise<void>;
  startVulnBackfill?: (
    since?: string,
    packageName?: string,
  ) => Promise<{ job?: VulnBackfillJobRow; alreadyRunning?: boolean }>;
  getVulnBackfill?: (id: string) => Promise<VulnBackfillJobRow | null>;
  /**
   * Sweep for packages whose CPE set has never been backfilled and start one. Scheduled, so
   * a newly tracked package acquires its CVE history without anyone remembering to ask.
   */
  autoBackfill?: () => Promise<{
    enabled: boolean;
    pending: number;
    started: string[];
    deferred: string[];
    failed: Array<{ package: string; error: string }>;
  }>;
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
        let result;
        try {
          result = await deps.runSync(packageName, { dryRun, triggerType: "scheduled" });
        } catch (error) {
          // A trigger that overlaps a running sync is expected, not an error. 409 keeps it
          // out of the 5xx bucket; Cloud Scheduler still sees a non-2xx and will retry.
          if (error instanceof SyncAlreadyRunningError) {
            res
              .status(409)
              .json({ code: "already_running", package: packageName, error: error.message });
            return;
          }
          throw error;
        }
        // The work is complete by the time this returns, so 200 — not 202.
        res.status(200).json({ package: packageName, dry_run: dryRun, result });
        return;
      }

      const results = await deps.runSyncAll({ dryRun, triggerType: "scheduled" });
      res.status(200).json({ dry_run: dryRun, results });
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
      const parsed = parseVulnSyncOptions(source, req.body);
      if (!parsed.ok) {
        res.status(400).json({ error: parsed.error });
        return;
      }

      if (parsed.opts.dryRun) {
        const preview = deps.vulnSync.cvssPreview;
        if (!preview) {
          res.status(503).json({ error: "cvss preview is not available" });
          return;
        }
        let result;
        try {
          result = await preview({ limit: parsed.opts.limit });
        } catch (err) {
          if (err instanceof VulnSyncAlreadyRunningError) {
            res.status(409).json({ code: "already_running", error: err.message });
            return;
          }
          throw err;
        }
        await deps.logAdminAction?.({
          action: "vuln-sync-preview",
          source,
          proposals: result.proposals.length,
          newly_blocked: result.newly_blocked.reduce((n, d) => n + d.newly_blocked.length, 0),
        });
        res.status(200).json({ source, dry_run: true, preview: result });
        return;
      }

      const outcomes = await runVulnSync(source, deps.vulnSync, parsed.opts);
      await deps.logAdminAction?.({ action: "vuln-sync", source, outcomes });
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
      const body = (req.body ?? {}) as { since?: unknown; package?: unknown };
      const since = typeof body.since === "string" ? body.since : undefined;
      if (body.since !== undefined && !since)
        return void res.status(400).json({ error: "since must be a YYYY-MM-DD string" });
      const packageName = typeof body.package === "string" ? body.package : undefined;
      if (body.package !== undefined && !packageName)
        return void res.status(400).json({ error: "package must be a string" });
      try {
        if (since) buildPublicationWindows(since);
      } catch (error) {
        return void res
          .status(400)
          .json({ error: error instanceof Error ? error.message : String(error) });
      }
      let result;
      try {
        result = await deps.startVulnBackfill(since, packageName);
      } catch (error) {
        // An unbackfillable package scope is a client error, not a 500.
        const message = error instanceof Error ? error.message : String(error);
        if (message.includes("No CPE pairs")) return void res.status(400).json({ error: message });
        throw error;
      }
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

  router.post("/vuln-backfill/auto", async (_req, res, next) => {
    try {
      if (!deps.autoBackfill) {
        res.status(503).json({ error: "Autonomous backfill is not available" });
        return;
      }
      const result = await deps.autoBackfill();
      if (!result.enabled) {
        // Disabled on purpose is a successful no-op, not a failure — a scheduler must not
        // turn red because an operator switched the sweep off.
        res.status(200).json({ enabled: false, message: "VULN_AUTO_BACKFILL is disabled" });
        return;
      }
      // Nothing pending, work deferred to the next sweep, and work started are all 200:
      // none of them is an error, and only a real failure should page anyone.
      res.status(result.failed.length > 0 ? 207 : 200).json(result);
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
