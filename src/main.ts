import express from "express";
import fs from "fs";
import path from "path";
import { config } from "./config/index.js";
import { log } from "./common/log.js";
import { pool, runMigrations } from "./db/client.js";
import { createStorageBackend } from "./storage/index.js";
import { loadAllPackages } from "./services/package-registry.js";
import { reconcileAllPackageVulns } from "./services/vuln-config.js";
import { createVulnSyncImpls } from "./vuln/sync/impls.js";
import { DownloadService, ChecksumAlgorithm } from "./services/download-service.js";
import { RetentionService } from "./services/retention-service.js";
import { SyncService, SyncRunOptions, SyncRunResult } from "./services/sync-service.js";
import { createPackagesRouter } from "./routes/packages.js";
import { createDownloadRouter } from "./routes/download.js";
import { buildRedownloadPath, createAdminRouter } from "./routes/admin.js";
import { createInternalRouter } from "./routes/internal.js";
import { createVulnsRouter } from "./routes/vulns.js";
import { createCvesRouter } from "./routes/cves.js";
import { createPackageVulnsRouter } from "./routes/package-vulns.js";
import { createAdminVulnsRouter } from "./routes/admin-vulns.js";
import { createApiDocsRouter } from "./routes/api-docs.js";
import { isPackageTracked } from "./db/queries/package-aliases.js";
import { crossReferenceVersions } from "./services/vuln-service.js";
import { queryVulns, VulnQueryDeps } from "./services/vuln-query.js";
import { getVulnHints } from "./services/vuln-hints.js";
import { insertAdminAction } from "./db/queries/admin-actions.js";
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
import { HealthResponseSchema } from "./routes/schemas.js";
import {
  getPackage,
  listPackages,
  setPackageEnabled,
  upsertPackage,
} from "./db/queries/packages.js";
import {
  deleteAllVersionsForPackage,
  deleteVersionGroup,
  getLatestVersionInGroup,
  getMaxAvailableVersionSort,
  getVersion,
  listAllArtifactsForPackage,
  listArtifactsInGroup,
  listVersionGroups,
  listVersionGroupSummaries,
  listVersions,
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
): Promise<Array<{ package: string; result: SyncRunResult }>> {
  const entries = Array.from(syncServices.entries());
  const results: Array<{ package: string; result: SyncRunResult }> = [];
  for (const [packageName, service] of entries) {
    const pkg = await getPackage(pool, packageName);
    if (pkg?.enabled === false) continue;
    const result = await service.run(options);
    results.push({ package: packageName, result });
  }
  return results;
}

async function startSyncAsync(
  packageName: string,
  opts: { triggerType: "admin" },
): Promise<number> {
  const service = syncServices.get(packageName);
  if (!service) throw new Error(`Unknown package: ${packageName}`);
  return service.startAsync(opts);
}

async function startVulnBackfill(since?: string) {
  const active = await getActiveVulnBackfillJob(pool);
  if (active) return { job: active, alreadyRunning: true };
  if (await isVulnSyncRunning(pool, "nvd")) return { alreadyRunning: true };
  let job;
  try {
    job = await createVulnBackfillJob(pool, since);
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

export function createApp(): express.Express {
  const app = express();
  app.set("json spaces", 2);
  app.use(express.json());
  app.use("/static", express.static(path.join(process.cwd(), "dist/public")));

  app.get("/", (_req, res) => {
    res.redirect("/admin/v1/");
  });

  app.get("/admin", (_req, res) => {
    res.redirect("/admin/v1/");
  });

  app.get("/health", async (_req, res, next) => {
    try {
      const [vuln_data_freshness, vuln_sync_status] = await Promise.all([
        getDataFreshness(pool).catch(() => null),
        getVulnSyncStatus(pool).catch(() => null),
      ]);
      res.json(
        HealthResponseSchema.parse({
          status: "ok",
          service: "walrus",
          vuln_data_freshness,
          vuln_sync_status,
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  app.use("/api", createApiDocsRouter());
  app.use("/openapi.json", createOpenApiRouter());

  const vulnQueryDeps: VulnQueryDeps = {
    resolvePackage: (query) => resolvePackage(pool, query),
    listAffectsForPackage: (name) => listAffectsWithCveForPackage(pool, name),
    getDataFreshness: () => getDataFreshness(pool),
    logUnresolved: (query, top) => logUnresolvedQuery(pool, query, top),
  };

  app.use(
    "/api/v1/vulns",
    createVulnsRouter({
      ...vulnQueryDeps,
      searchAliases: (q) => searchAliases(pool, q),
      getProductMetadata: (name) => getVulnProductMetadata(pool, name),
    }),
  );

  app.use(
    "/admin/v1",
    createAdminVulnsRouter({
      queryVulns: (product, version) => queryVulns(vulnQueryDeps, { product, version }),
      getDataFreshness: () => getDataFreshness(pool),
      getSyncStatus: () => getVulnSyncStatus(pool),
      getHints: () => getVulnHints(pool),
      vulnSyncImpls,
      logAdminAction: (details) => insertAdminAction(pool, { action_type: "vuln-sync", details }),
      startVulnBackfill,
      getVulnBackfill: (id) => getVulnBackfillJob(pool, id),
    }),
  );

  app.use(
    "/api/v1/cves",
    createCvesRouter({
      getCve: (cveId) => getCveById(pool, cveId),
      listAffectedPackages: (cveId) => listAffectedPackagesForCve(pool, cveId),
      getDataFreshness: () => getDataFreshness(pool),
    }),
  );

  app.use(
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
    }),
  );

  app.use(
    "/api/v1/packages",
    createPackagesRouter({
      listEnabledPackages: () => listPackages(pool, true),
      getPackage: (name) => getPackage(pool, name),
      listVersionGroups: (packageName) => listVersionGroups(pool, packageName),
      listVersionGroupSummaries: (packageName, opts) =>
        listVersionGroupSummaries(pool, packageName, opts),
      listVersions: (packageName, opts) => listVersions(pool, packageName, opts),
      getLatestVersionInGroup: (packageName, group, opts) =>
        getLatestVersionInGroup(pool, packageName, group, opts),
      listArtifactsForVersion: (versionId) => listArtifactsForVersion(pool, versionId),
      getRecentSyncJob: (packageName, withinMinutes) =>
        getRecentSyncJob(pool, packageName, withinMinutes),
      triggerOnDemandSync: async (packageName) => {
        await runSync(packageName, { triggerType: "on-demand" });
      },
    }),
  );

  app.use(
    "/download",
    createDownloadRouter({
      getVersion: (packageName, version) => getVersion(pool, packageName, version),
      getArtifact: (versionId, os, arch) => getArtifact(pool, versionId, os, arch),
      streamFromStorage: (key) => storage.stream(key),
    }),
  );

  app.use(
    "/admin/v1",
    createAdminRouter({
      listConfiguredPackages: () => Array.from(syncServices.keys()),
      getConfiguredPackageMeta: () =>
        configs.map((c) => ({ name: c.name, display_name: c.display_name, vendor: c.vendor })),
      runSync: (packageName, opts) => runSync(packageName, opts),
      runSyncAll: (opts) => runSyncAll(opts),
      startSyncAsync,
      getArtifactByPackageVersionPlatform: async (packageName, version, os, arch) => {
        const versionRow = await getVersion(pool, packageName, version);
        if (!versionRow) return null;
        const artifact = await getArtifact(pool, versionRow.id, os, arch);
        if (!artifact) return null;
        return { artifact, version: versionRow.version };
      },
      redownloadArtifact: async (artifact, packageName, version) => {
        const request = {
          artifactId: artifact.id,
          upstreamUrl: artifact.upstream_url,
          storagePath: buildRedownloadPath(packageName, version, artifact),
          expectedChecksum: artifact.checksum ?? undefined,
          checksumType: normalizeChecksumType(artifact.checksum_type),
        };
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
        const cooling_off_threshold = await getMaxAvailableVersionSort(
          pool,
          detail.job.package_name,
        );
        return {
          ...detail,
          cooling_off_days: pkgConfig?.retention.cooling_off_days,
          cooling_off_threshold,
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
          { total: number; critical: number; high: number; kev: number }
        > = {};
        for (const v of perVersion) {
          byVersion[v.version] = {
            total: v.counts.total,
            critical: v.counts.critical,
            high: v.counts.high,
            kev: v.counts.kev,
          };
        }
        return { tracked: true, byVersion };
      },
    }),
  );

  app.use(
    "/internal",
    createInternalRouter({
      runSync: (packageName, opts) => runSync(packageName, opts),
      runSyncAll: (opts) => runSyncAll(opts),
      vulnSync: vulnSyncImpls,
      vulnHints: () => getVulnHints(pool),
      startVulnBackfill,
      getVulnBackfill: (id) => getVulnBackfillJob(pool, id),
    }),
  );

  app.use(
    (err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
      const message = err instanceof Error ? err.message : "Internal server error";
      log.error({ err }, "Request failed");
      res.status(500).json({ error: message });
    },
  );

  return app;
}

const app = createApp();

if (require.main === module) {
  runMigrations()
    .then(() => recoverInterruptedState())
    .then(() => reconcileAllPackageVulns(pool, configs))
    .then(() => {
      log.info("Startup recovery complete");
      app.listen(config.PORT, () => {
        log.info({ port: config.PORT }, "Walrus started");
      });
    })
    .catch((err) => {
      log.error({ err }, "Startup recovery failed");
      process.exit(1);
    });
}

export default app;

function normalizeChecksumType(type: string | null): ChecksumAlgorithm | undefined {
  if (type === "sha256" || type === "sha1") {
    return type;
  }
  return undefined;
}
