import express from "express";
import type { RequestHandler } from "express";
import fs from "fs";
import path from "path";
import packageMetadata from "../package.json";
import { config } from "./config/index.js";
import { log } from "./common/log.js";
import { pool, runMigrations } from "./db/client.js";
import { createStorageBackend } from "./storage/index.js";
import { loadAllPackages } from "./services/package-registry.js";
import { reconcileAllPackageVulns } from "./services/vuln-config.js";
import { createVulnSyncImpls } from "./vuln/sync/impls.js";
import { DownloadService } from "./services/download-service.js";
import { RetentionService } from "./services/retention-service.js";
import {
  SyncAlreadyRunningError,
  SyncService,
  SyncRunOptions,
  SyncRunResult,
} from "./services/sync-service.js";
import { createPackagesRouter } from "./routes/packages.js";
import { createDownloadRouter } from "./routes/download.js";
import { buildRedownloadRequest, createAdminRouter } from "./routes/admin.js";
import { createInternalRouter } from "./routes/internal.js";
import { createVulnsRouter } from "./routes/vulns.js";
import { createCvesRouter } from "./routes/cves.js";
import { createPackageVulnsRouter } from "./routes/package-vulns.js";
import { createAdminVulnsRouter } from "./routes/admin-vulns.js";
import { createApiDocsRouter } from "./routes/api-docs.js";
import { isPackageTracked, listDistinctCpePairs } from "./db/queries/package-aliases.js";
import { crossReferenceVersions, getVersionAvailabilityStatus } from "./services/vuln-service.js";
import { queryVulns, VulnQueryDeps } from "./services/vuln-query.js";
import { getVulnHints } from "./services/vuln-hints.js";
import { getDegradations } from "./services/degradations.js";
import { autoBackfillPendingPackages } from "./services/vuln-backfill-autostart.js";
import {
  listAvailabilityHistory,
  listRecentTransitions,
  recordAvailabilityTransitions,
} from "./services/availability-history.js";
import { insertAdminAction, listSuppressionAuditActions } from "./db/queries/admin-actions.js";
import { resolvePackage } from "./vuln/resolver.js";
import {
  listAffectsWithCveForPackage,
  getCveById,
  listAffectedPackagesForCve,
} from "./db/queries/cves.js";
import { getVulnProductMetadata, searchAliases } from "./db/queries/package-aliases.js";
import { getDataFreshness, getVulnSyncStatus } from "./db/queries/vuln-sync-state.js";
import { logUnresolvedQuery } from "./db/queries/unresolved-queries.js";
import { createOpenApiRouter } from "./routes/openapi.js";
import { createHealthRouter } from "./routes/health.js";
import { renderLandingPage } from "./routes/page-shell.js";
import { LandingPageResponseSchema } from "./routes/schemas.js";
import {
  getPackage,
  listPackages,
  setPackageEnabled,
  upsertPackage,
} from "./db/queries/packages.js";
import {
  deleteAllVersionsForPackage,
  deleteVersionGroup,
  getVersion,
  listAllArtifactsForPackage,
  listArtifactsInGroup,
  listAvailableVersionsInGroup,
  listAvailableVersionsByGroup,
  getEarliestCoolingOffInGroup,
  listVersionGroups,
  listVersionGroupsWithLts,
  listVersions,
  resyncVersionSortKeys,
} from "./db/queries/versions.js";
import {
  getArtifact,
  listArtifactsForVersion,
  listFailedArtifacts,
  listPendingArtifacts,
  updateArtifactStatus,
} from "./db/queries/artifacts.js";
import { getRecentSyncJob, getJobWithArtifacts, listSyncJobs } from "./db/queries/sync-jobs.js";
import {
  createVulnBackfillJob,
  getActiveVulnBackfillJob,
  getVulnBackfillJob,
  updateVulnBackfillJob,
} from "./db/queries/vuln-backfill-jobs.js";
import { CloudRunBackfillLauncher, LocalBackfillLauncher } from "./vuln/backfill-launcher.js";
import { isVulnSyncRunning } from "./vuln/sync/lock.js";
import {
  countActiveCveSuppressions,
  getActiveCveSuppressionSummary,
  listActiveCveSuppressions,
} from "./db/queries/cve-suppressions.js";
import {
  createAuditedCveSuppression,
  previewCveSuppression,
  previewCveSuppressionRevocation,
  revokeAuditedCveSuppression,
} from "./services/cve-suppression-service.js";
import { installOperatorAuth } from "./authn/operator.js";
import { loadOperatorAuthRuntime, type OperatorAuthRuntime } from "./authn/runtime.js";
import { loadMachineAuth } from "./authn/google-oidc.js";
import { createAuthAuditSinks } from "./authn/audit.js";

const storage = createStorageBackend();
const vulnSyncImpls = createVulnSyncImpls(pool);
const backfillLauncher =
  config.NODE_ENV === "production"
    ? new CloudRunBackfillLauncher()
    : new LocalBackfillLauncher(pool);
const packageRegistry = loadAllPackages();
if (packageRegistry.errors.length > 0) {
  for (const error of packageRegistry.errors) {
    log.warn({ file: error.filePath, error: error.error }, "Package config failed to load");
  }
}

const configs = packageRegistry.configs.map((entry) => entry.config);
const syncServices = new Map<string, SyncService>();
const sharedDownloadService = new DownloadService(pool, storage, { maxRetries: 2 });
const applicationStartedAt = new Date();

for (const packageConfig of configs) {
  const packageDownloadService = new DownloadService(pool, storage, { maxRetries: 2 });
  const retentionService = new RetentionService(pool, storage);
  const syncService = new SyncService(
    pool,
    packageConfig,
    packageDownloadService,
    retentionService,
    {
      syncConcurrency: config.SYNC_CONCURRENCY,
      downloadConcurrency: config.DOWNLOAD_CONCURRENCY,
    },
  );
  syncServices.set(packageConfig.name, syncService);
}

/**
 * `version_sort` is written once per row and never revisited, so a change to the sort-key
 * algorithm has to be applied to existing rows by something. Boot is that something — the
 * service has no shell to run a fixup from (see `resyncVersionSortKeys`).
 */
async function repairDerivedSortKeys(): Promise<void> {
  const repaired = await resyncVersionSortKeys(pool);
  if (repaired > 0) {
    log.info({ repaired }, "Recomputed stale version_sort keys");
  }
}

async function recoverInterruptedState(): Promise<void> {
  await pool.query(
    `UPDATE artifacts SET status = 'failed', error_message = 'interrupted by restart'
     WHERE status = 'downloading'`,
  );
  await pool.query(
    `UPDATE sync_jobs SET status = 'failed', error_message = 'interrupted by restart',
       completed_at = now()
     WHERE status = 'running'`,
  );
}

async function runSync(packageName: string, options: SyncRunOptions): Promise<SyncRunResult> {
  const service = syncServices.get(packageName);
  if (!service) {
    throw new Error(`Unknown package: ${packageName}`);
  }
  const pkg = await getPackage(pool, packageName);
  if (pkg?.enabled === false) {
    throw new Error(`Package '${packageName}' is disabled`);
  }
  return service.run(options);
}

async function runSyncAll(
  options: SyncRunOptions,
): Promise<Array<{ package: string; result?: SyncRunResult; skipped?: string }>> {
  const entries = Array.from(syncServices.entries());
  const results: Array<{ package: string; result?: SyncRunResult; skipped?: string }> = [];
  for (const [packageName, service] of entries) {
    const pkg = await getPackage(pool, packageName);
    if (pkg?.enabled === false) continue;
    try {
      results.push({ package: packageName, result: await service.run(options) });
    } catch (error) {
      // One package already syncing is a normal outcome of overlapping triggers, not a
      // failed run — report it and carry on rather than aborting the remaining packages.
      if (error instanceof SyncAlreadyRunningError) {
        log.info({ package: packageName }, "Skipping package: sync already running");
        results.push({ package: packageName, skipped: "already_running" });
        continue;
      }
      throw error;
    }
  }
  return results;
}

async function startSyncAsync(packageName: string, opts: SyncRunOptions): Promise<number> {
  const service = syncServices.get(packageName);
  if (!service) throw new Error(`Unknown package: ${packageName}`);
  return service.startAsync(opts);
}

async function startVulnBackfill(since?: string, packageName?: string) {
  // Reject an unbackfillable scope up front rather than launching a job that
  // would walk zero CPE pairs and report success.
  if (packageName) {
    const pairs = await listDistinctCpePairs(pool, packageName);
    if (pairs.length === 0) {
      throw new Error(
        `No CPE pairs for package '${packageName}' — nothing to backfill from NVD. ` +
          `Packages tracked only via OSV have no CPE pairs; use the OSV sync for those.`,
      );
    }
  }
  const active = await getActiveVulnBackfillJob(pool);
  if (active) return { job: active, alreadyRunning: true };
  if (await isVulnSyncRunning(pool, "nvd")) return { alreadyRunning: true };
  let job;
  try {
    job = await createVulnBackfillJob(pool, since, packageName);
  } catch (error) {
    if ((error as { code?: string }).code === "23505") {
      const raced = await getActiveVulnBackfillJob(pool);
      if (raced) return { job: raced, alreadyRunning: true };
    }
    throw error;
  }
  try {
    const executionName = await backfillLauncher.launch(job.id);
    await updateVulnBackfillJob(pool, job.id, { execution_name: executionName });
    return { job: (await getVulnBackfillJob(pool, job.id)) ?? job };
  } catch (error) {
    await updateVulnBackfillJob(pool, job.id, {
      status: "failed",
      finished_at: new Date(),
      error_message: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}

export interface CreateAppOptions {
  operatorAuth?: OperatorAuthRuntime;
  internalAuth?: RequestHandler;
  health?: {
    startedAt?: Date;
    now?: () => Date;
    checkDatabase?: () => Promise<void>;
  };
}

export const SECURITY_TIER_MOUNTS = [
  { tier: "operator", prefix: "/admin/v1" },
  { tier: "machine", prefix: "/internal" },
  { tier: "public", prefix: "/" },
] as const;

export type SecurityTier = (typeof SECURITY_TIER_MOUNTS)[number]["tier"];
export interface SecurityTierMount {
  tier: SecurityTier;
  prefix: string;
  router: express.Router;
}

export function createApp(options: CreateAppOptions = {}): express.Express {
  const app = express();
  // Cloud Run terminates TLS and supplies the original scheme/client address through one
  // trusted proxy hop. Origin checks and login throttling must see those external values.
  app.set("trust proxy", 1);
  app.set("json spaces", 2);
  app.use(express.json());
  // The admin UI posts plain HTML forms. Without this, every form field is silently dropped and
  // the handler sees an empty body — which turned "Backfill this package" into an unscoped
  // backfill of all 11 packages, since a missing `package` means "everything" (WAL-71).
  app.use(express.urlencoded({ extended: false }));
  const publicRouter = express.Router();
  publicRouter.use("/static", express.static(path.join(process.cwd(), "dist/public")));

  const operatorRouter = express.Router();
  if (options.operatorAuth) {
    installOperatorAuth(operatorRouter, options.operatorAuth);
  } else {
    operatorRouter.use((_req, res) =>
      res.status(503).json({ error: "Operator authentication unavailable" }),
    );
  }
  publicRouter.get("/", (_req, res) => {
    res
      .type("html")
      .send(LandingPageResponseSchema.parse(renderLandingPage(packageMetadata.version)));
  });

  publicRouter.get("/admin", (_req, res) => {
    res.redirect("/admin/v1/");
  });

  publicRouter.use(
    createHealthRouter({
      metadata: { gitUrl: packageMetadata.gitUrl, version: packageMetadata.version },
      startedAt: options.health?.startedAt ?? applicationStartedAt,
      now: options.health?.now,
      checkDatabase:
        options.health?.checkDatabase ??
        (async () => {
          await pool.query("SELECT 1");
        }),
      getStatusDetails: async () => {
        const [vuln_data_freshness, vuln_sync_status, cve_suppressions, degradations] =
          await Promise.all([
            getDataFreshness(pool).catch(() => null),
            getVulnSyncStatus(pool).catch(() => null),
            getActiveCveSuppressionSummary(pool).catch(() => null),
            getDegradations(pool, { autoBackfillEnabled: config.VULN_AUTO_BACKFILL }).catch(
              () => [],
            ),
          ]);
        return { vuln_data_freshness, vuln_sync_status, cve_suppressions, degradations };
      },
    }),
  );

  publicRouter.use("/api", createApiDocsRouter());
  publicRouter.use("/openapi.json", createOpenApiRouter());

  const vulnQueryDeps: VulnQueryDeps = {
    resolvePackage: (query) => resolvePackage(pool, query),
    listAffectsForPackage: (name) => listAffectsWithCveForPackage(pool, name),
    getDataFreshness: () => getDataFreshness(pool),
    logUnresolved: (query, top) => logUnresolvedQuery(pool, query, top),
  };

  publicRouter.use(
    "/api/v1/vulns",
    createVulnsRouter({
      ...vulnQueryDeps,
      searchAliases: (q) => searchAliases(pool, q),
      getProductMetadata: (name) => getVulnProductMetadata(pool, name),
    }),
  );

  operatorRouter.use(
    createAdminVulnsRouter({
      queryVulns: (product, version) => queryVulns(vulnQueryDeps, { product, version }),
      getDataFreshness: () => getDataFreshness(pool),
      getSyncStatus: () => getVulnSyncStatus(pool),
      getHints: () => getVulnHints(pool, { autoBackfillEnabled: config.VULN_AUTO_BACKFILL }),
      vulnSyncImpls,
      logAdminAction: (details, subject) =>
        insertAdminAction(pool, {
          action_type: "vuln-sync",
          performed_by: subject,
          details,
        }),
      recordAvailability: (source) =>
        recordAvailabilityTransitions(pool, { source, trigger: "admin" }),
      startVulnBackfill,
      getVulnBackfill: (id) => getVulnBackfillJob(pool, id),
      getActiveSuppressionCount: () => countActiveCveSuppressions(pool),
      listActiveSuppressions: () => listActiveCveSuppressions(pool),
      listSuppressionAudit: (opts) => listSuppressionAuditActions(pool, opts),
      cveExists: async (cveId) => (await getCveById(pool, cveId)) !== null,
      packageExists: async (packageName) => (await getPackage(pool, packageName)) !== null,
      previewSuppression: (input) => previewCveSuppression(pool, input),
      createSuppression: (input) => createAuditedCveSuppression(pool, input),
      previewSuppressionRevocation: (id) => previewCveSuppressionRevocation(pool, id),
      revokeSuppression: (input) => revokeAuditedCveSuppression(pool, input),
    }),
  );

  publicRouter.use(
    "/api/v1/cves",
    createCvesRouter({
      getCve: (cveId) => getCveById(pool, cveId),
      listAffectedPackages: (cveId) => listAffectedPackagesForCve(pool, cveId),
      getDataFreshness: () => getDataFreshness(pool),
    }),
  );

  publicRouter.use(
    "/api/v1/packages",
    createPackageVulnsRouter({
      packageExists: async (name) => (await getPackage(pool, name)) !== null,
      isTracked: (name) => isPackageTracked(pool, name),
      listCachedVersions: async (name, version) => {
        const rows = await listVersions(pool, name, {});
        const mapped = rows.map((r) => ({ version: r.version, version_group: r.version_group }));
        return version ? mapped.filter((v) => v.version === version) : mapped;
      },
      listAffectsForPackage: (name) => listAffectsWithCveForPackage(pool, name),
      getDataFreshness: () => getDataFreshness(pool),
      listAvailabilityHistory: (name, version) => listAvailabilityHistory(pool, name, version),
      listRecentTransitions: (name) => listRecentTransitions(pool, name),
    }),
  );

  publicRouter.use(
    "/api/v1/packages",
    createPackagesRouter({
      listEnabledPackages: () => listPackages(pool, true),
      getPackage: (name) => getPackage(pool, name),
      listVersionGroups: (packageName) => listVersionGroups(pool, packageName),
      listVersionGroupsWithLts: (packageName) => listVersionGroupsWithLts(pool, packageName),
      getEarliestCoolingOffInGroup: (packageName, group, opts) =>
        getEarliestCoolingOffInGroup(pool, packageName, group, opts),
      listAvailableVersionsByGroup: (packageName, opts) =>
        listAvailableVersionsByGroup(pool, packageName, opts),
      listAffectsForPackage: (name) => listAffectsWithCveForPackage(pool, name),
      listVersions: (packageName, opts) => listVersions(pool, packageName, opts),
      listAvailableVersionsInGroup: (packageName, group, opts) =>
        listAvailableVersionsInGroup(pool, packageName, group, opts),
      listArtifactsForVersion: (versionId) => listArtifactsForVersion(pool, versionId),
      getRecentSyncJob: (packageName, withinMinutes) =>
        getRecentSyncJob(pool, packageName, withinMinutes),
      triggerOnDemandSync: async (packageName) => {
        await runSync(packageName, { triggerType: "on-demand" });
      },
    }),
  );

  publicRouter.use(
    "/download",
    createDownloadRouter({
      getVersion: (packageName, version) => getVersion(pool, packageName, version),
      getPackageRow: (packageName) => getPackage(pool, packageName),
      listAffectsForPackage: (packageName) => listAffectsWithCveForPackage(pool, packageName),
      getArtifact: (versionId, os, arch) => getArtifact(pool, versionId, os, arch),
      streamFromStorage: (key, range) => storage.stream(key, range),
    }),
  );

  operatorRouter.use(
    createAdminRouter({
      listConfiguredPackages: () => Array.from(syncServices.keys()),
      getConfiguredPackageMeta: () =>
        configs.map((c) => ({ name: c.name, display_name: c.display_name, vendor: c.vendor })),
      runSync: (packageName, opts) => runSync(packageName, opts),
      runSyncAll: (opts) => runSyncAll(opts),
      startSyncAsync,
      startHistoricalBackfill: (packageName, opts) => startSyncAsync(packageName, opts),
      getArtifactByPackageVersionPlatform: async (packageName, version, os, arch) => {
        const versionRow = await getVersion(pool, packageName, version);
        if (!versionRow) return null;
        const artifact = await getArtifact(pool, versionRow.id, os, arch);
        if (!artifact) return null;
        return { artifact, version: versionRow.version };
      },
      redownloadArtifact: async (artifact, packageName, version) => {
        const request = buildRedownloadRequest(
          packageName,
          version,
          artifact,
          configs.find((c) => c.name === packageName),
        );
        return sharedDownloadService.downloadArtifact(request, false);
      },
      listArtifactsByPackageVersion: async (packageName, version, platform) => {
        const versionRow = await getVersion(pool, packageName, version);
        if (!versionRow) return [];
        const artifacts = await listArtifactsForVersion(pool, versionRow.id);
        if (!platform) return artifacts;
        return artifacts.filter(
          (artifact) => artifact.os === platform.os && artifact.arch === platform.arch,
        );
      },
      removeArtifact: async (artifact) => {
        if (artifact.gcs_path) {
          await storage.delete(artifact.gcs_path);
        }
        await updateArtifactStatus(pool, artifact.id, {
          status: "removed",
          removed_at: new Date(),
        });
      },
      listFailedArtifacts: (opts) => listFailedArtifacts(pool, opts),
      listPendingArtifacts: (opts) => listPendingArtifacts(pool, opts),
      listJobs: (opts) => listSyncJobs(pool, opts),
      getJob: async (id) => {
        const detail = await getJobWithArtifacts(pool, id);
        if (!detail) return null;
        const pkgConfig = packageRegistry.configs.find(
          (e) => e.config.name === detail.job.package_name,
        )?.config;
        return {
          ...detail,
          cooling_off_days: pkgConfig?.retention.cooling_off_days,
        };
      },
      removeAllVersionGroups: async (packageName) => {
        const artifacts = await listAllArtifactsForPackage(pool, packageName);
        for (const a of artifacts) {
          if (a.gcs_path) {
            await storage.delete(a.gcs_path);
          }
        }
        const { versionsDeleted, artifactsDeleted } = await deleteAllVersionsForPackage(
          pool,
          packageName,
        );
        return { versions: versionsDeleted, artifacts: artifactsDeleted };
      },
      removeVersionGroup: async (packageName, group) => {
        const artifacts = await listArtifactsInGroup(pool, packageName, group);
        for (const a of artifacts) {
          if (a.gcs_path) {
            await storage.delete(a.gcs_path);
          }
        }
        const { versionsDeleted, artifactsDeleted } = await deleteVersionGroup(
          pool,
          packageName,
          group,
        );
        return { versions: versionsDeleted, artifacts: artifactsDeleted };
      },
      setPackageEnabled: async (packageName, enabled) => {
        const config = configs.find((c) => c.name === packageName);
        if (!config) return false;
        // Ensure the DB row exists (package may not have synced yet)
        await upsertPackage(pool, {
          name: config.name,
          display_name: config.display_name,
          vendor: config.vendor,
          description: config.description ?? null,
          website: config.website ?? null,
          config_hash: "",
          enabled,
        });
        // upsertPackage no longer updates enabled on conflict, so set it explicitly
        await setPackageEnabled(pool, packageName, enabled);
        return true;
      },
      isPackageEnabled: async (packageName) => {
        const pkg = await getPackage(pool, packageName);
        return pkg?.enabled ?? null;
      },
      listAllPackages: () => listPackages(pool),
      listVersionGroupNamesForPackage: (packageName) => listVersionGroups(pool, packageName),
      listVersionsInGroup: (packageName, group) => listVersions(pool, packageName, { group }),
      listArtifactsForVersionId: (versionId) => listArtifactsForVersion(pool, versionId),
      getTomlSource: (name: string) => {
        const entry = packageRegistry.configs.find((e) => e.config.name === name);
        if (!entry) return null;
        try {
          return fs.readFileSync(entry.filePath, "utf-8");
        } catch {
          return null;
        }
      },
      getPackageVulnBadges: async (name: string) => {
        if (!(await isPackageTracked(pool, name))) return { tracked: false, byVersion: {} };
        const versionRows = await listVersions(pool, name, {});
        const affects = await listAffectsWithCveForPackage(pool, name);
        const perVersion = crossReferenceVersions(
          versionRows.map((r) => ({ version: r.version, version_group: r.version_group })),
          affects,
        );
        const byVersion: Record<
          string,
          { total: number; critical: number; high: number; kev: number; blocked: boolean }
        > = {};
        for (const v of perVersion) {
          byVersion[v.version] = {
            total: v.counts.total,
            critical: v.counts.critical,
            high: v.counts.high,
            kev: v.counts.kev,
            // Same predicate the download route enforces, over the affects rows already loaded.
            blocked: getVersionAvailabilityStatus(v.version, affects) === "blocked",
          };
        }
        return { tracked: true, byVersion };
      },
    }),
  );

  const internalRouter = express.Router();
  internalRouter.use(
    options.internalAuth ??
      ((_req, res) => res.status(503).json({ error: "Machine authentication unavailable" })),
  );
  internalRouter.use(
    createInternalRouter({
      runSync: (packageName, opts) => runSync(packageName, opts),
      runSyncAll: (opts) => runSyncAll(opts),
      vulnSync: vulnSyncImpls,
      vulnHints: () => getVulnHints(pool, { autoBackfillEnabled: config.VULN_AUTO_BACKFILL }),
      // performed_by distinguishes these from the admin UI's rows: /internal is
      // machine-triggered (Cloud Scheduler), so the trail can tell an unattended
      // gate change from one an operator made.
      logAdminAction: (details, subject) =>
        insertAdminAction(pool, {
          action_type: "vuln-sync",
          performed_by: subject,
          details,
        }),
      recordAvailability: (source) =>
        recordAvailabilityTransitions(pool, { source, trigger: "internal" }),
      autoBackfill: async () => {
        if (!config.VULN_AUTO_BACKFILL) {
          return { enabled: false, pending: 0, started: [], deferred: [], failed: [] };
        }
        const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });
        return { enabled: true, ...result };
      },
    }),
  );

  const securityTierMounts: SecurityTierMount[] = [
    { ...SECURITY_TIER_MOUNTS[0], router: operatorRouter },
    { ...SECURITY_TIER_MOUNTS[1], router: internalRouter },
    { ...SECURITY_TIER_MOUNTS[2], router: publicRouter },
  ];
  app.locals.securityTierMounts = securityTierMounts;
  for (const mount of securityTierMounts) app.use(mount.prefix, mount.router);

  app.use(
    (err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      const message = err instanceof Error ? err.message : "Internal server error";
      log.error({ err }, "Request failed");
      res.status(500).json({ error: message });
    },
  );

  return app;
}

async function start(): Promise<void> {
  const authAudit = createAuthAuditSinks(pool);
  const operatorAuth = await loadOperatorAuthRuntime(config, {
    auditLogin: authAudit.auditLogin,
    auditAction: authAudit.auditAction,
  });
  const internalAuth = loadMachineAuth(config, authAudit.auditMachine);
  await runMigrations();
  await repairDerivedSortKeys();
  await recoverInterruptedState();
  await reconcileAllPackageVulns(pool, configs);
  const app = createApp({ operatorAuth, internalAuth });
  log.info("Startup recovery complete");
  app.listen(config.PORT, () => {
    log.info({ port: config.PORT }, "Walrus started");
  });
}

if (require.main === module) {
  void start().catch((err) => {
    log.error({ err }, "Startup recovery failed");
    process.exit(1);
  });
}

export default createApp;
