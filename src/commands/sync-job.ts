/**
 * sync-job.ts — run a package sync to completion as a Cloud Run Job.
 *
 * The scheduled sync used to be an HTTP POST to /internal/sync that performed the whole
 * sync inside the request. Cloud Scheduler abandons a request after its attempt deadline
 * (30 minutes at most), and Cloud Run throttles CPU once a response is sent, so neither
 * "wait for it" nor "respond early and keep working" is safe for work of this length.
 *
 * A Job is the platform's answer: its own container, run to completion, with no request
 * to outlive. See ADR-004 commitment 1.
 *
 * Usage:
 *   node dist/commands/sync-job.js                  # every enabled package
 *   node dist/commands/sync-job.js --package golang # one package
 */
import { config } from "../config/index.js";
import { log } from "../common/log.js";
import { pool, runMigrations } from "../db/client.js";
import { createStorageBackend } from "../storage/index.js";
import { loadAllPackages } from "../services/package-registry.js";
import { DownloadService } from "../services/download-service.js";
import { RetentionService } from "../services/retention-service.js";
import { SyncAlreadyRunningError, SyncService } from "../services/sync-service.js";
import { getPackage } from "../db/queries/packages.js";

export function parsePackageArg(args: string[]): string | undefined {
  const i = args.indexOf("--package");
  if (i < 0) return undefined;
  const value = args[i + 1];
  if (!value || value.startsWith("--")) throw new Error("--package requires a package name");
  return value;
}

async function main(): Promise<void> {
  const only = parsePackageArg(process.argv.slice(2));
  await runMigrations();

  const registry = loadAllPackages();
  for (const error of registry.errors) {
    log.warn({ file: error.filePath, error: error.error }, "Package config failed to load");
  }

  const storage = createStorageBackend();
  const configs = registry.configs
    .map((entry) => entry.config)
    .filter((c) => only === undefined || c.name === only);

  if (only !== undefined && configs.length === 0) {
    throw new Error(`Unknown package: ${only}`);
  }

  let failed = 0;
  let skipped = 0;
  for (const packageConfig of configs) {
    const pkg = await getPackage(pool, packageConfig.name);
    if (pkg?.enabled === false) {
      log.info({ package: packageConfig.name }, "Skipping disabled package");
      continue;
    }

    const service = new SyncService(
      pool,
      packageConfig,
      new DownloadService(pool, storage, { maxRetries: 2 }),
      new RetentionService(pool, storage),
      {
        syncConcurrency: config.SYNC_CONCURRENCY,
        downloadConcurrency: config.DOWNLOAD_CONCURRENCY,
      },
    );

    try {
      const result = await service.run({ triggerType: "scheduled" });
      log.info({ package: packageConfig.name, result }, "Package sync complete");
    } catch (error) {
      // Contention is a normal outcome of overlapping triggers, and a failure of one
      // package must not strand the rest — record both and keep going.
      if (error instanceof SyncAlreadyRunningError) {
        skipped += 1;
        log.info({ package: packageConfig.name }, "Skipping package: sync already running");
        continue;
      }
      failed += 1;
      log.error({ package: packageConfig.name, err: error }, "Package sync failed");
    }
  }

  log.info({ packages: configs.length, failed, skipped }, "Sync job finished");
  // A non-zero exit marks the Cloud Run Job execution failed, which is what should page.
  // Skipped-because-locked is not a failure.
  if (failed > 0) throw new Error(`${failed} package sync(s) failed`);
}

if (require.main === module) {
  main()
    .then(() => pool.end())
    .then(() => process.exit(0))
    .catch(async (error) => {
      log.error({ err: error }, "Sync job failed");
      await pool.end().catch(() => {});
      process.exit(1);
    });
}
