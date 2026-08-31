import crypto from "crypto";
import { Pool } from "pg";
import { mapWithConcurrency } from "../common/async-utils.js";
import { generateSortKey } from "../common/version-utils.js";
import { AdvisoryLockUnavailableError, withAdvisoryLock } from "../common/advisory-lock.js";
import { computeCoolingOffUntil, selectRetentionWindow } from "../common/retention-window.js";
import { log } from "../common/log.js";
import { getStrategy } from "../discovery/index.js";
import { DiscoveredVersion, DiscoveryOptions } from "../discovery/types.js";
import { SyncJobTrigger } from "../types/db.js";
import { insertArtifact, updateArtifactStatus } from "../db/queries/artifacts.js";
import { upsertPackage } from "../db/queries/packages.js";
import { createSyncJob, incrementJobCounters, updateSyncJob } from "../db/queries/sync-jobs.js";
import { getMaxAvailableVersionSort, insertVersion } from "../db/queries/versions.js";
import { buildArtifactPath } from "../storage/types.js";
import { PackageConfig } from "../types/package-config.js";
import { renderServedFilename } from "../transform/index.js";
import { SyncJobRow } from "../types/db.js";
import { DownloadRequest, DownloadResult, DownloadService } from "./download-service.js";
import { RetentionResult, RetentionService } from "./retention-service.js";

export interface SyncRunOptions {
  triggerType?: SyncJobTrigger;
  dryRun?: boolean;
  discovery?: DiscoveryOptions;
}

export interface SyncRunResult {
  dryRun: boolean;
  versionsFound: number;
  artifactsQueued: number;
  downloaded: number;
  failed: number;
  retention: RetentionResult;
  jobId?: number;
}

interface SyncDeps {
  discoverVersions: (
    config: PackageConfig,
    options?: DiscoveryOptions,
  ) => Promise<DiscoveredVersion[]>;
  upsertPackage: typeof upsertPackage;
  createSyncJob: typeof createSyncJob;
  updateSyncJob: typeof updateSyncJob;
  incrementJobCounters: typeof incrementJobCounters;
  insertVersion: typeof insertVersion;
  insertArtifact: typeof insertArtifact;
  updateArtifactStatus: typeof updateArtifactStatus;
  downloadArtifact: (req: DownloadRequest, dryRun: boolean) => Promise<DownloadResult>;
  enforceRetention: (
    packageName: string,
    keep: number,
    dryRun: boolean,
    groupsToKeep?: number,
  ) => Promise<RetentionResult>;
  getMaxAvailableVersionSort: typeof getMaxAvailableVersionSort;
}

export interface SyncServiceOptions {
  syncConcurrency?: number;
  downloadConcurrency?: number;
  deps?: Partial<SyncDeps>;
}

const SYNC_LOCK_NAMESPACE = "walrus:package-sync";

/**
 * Raised when a sync for this package is already in flight. Locking is per package, not
 * global: two different packages never touch the same rows, so serialising them would only
 * make a full run slower. Two runs of the *same* package race on its versions and artifacts.
 */
export class SyncAlreadyRunningError extends Error {
  constructor(readonly packageName: string) {
    super(`sync for package '${packageName}' is already running`);
    this.name = "SyncAlreadyRunningError";
  }
}

export class SyncService {
  private readonly syncConcurrency: number;
  private readonly downloadConcurrency: number;
  private readonly deps: SyncDeps;

  constructor(
    private readonly pool: Pool,
    private readonly packageConfig: PackageConfig,
    private readonly downloadService: DownloadService,
    private readonly retentionService: RetentionService,
    opts: SyncServiceOptions = {},
  ) {
    this.syncConcurrency = opts.syncConcurrency ?? 4;
    this.downloadConcurrency = opts.downloadConcurrency ?? 2;
    this.deps = {
      discoverVersions: (config, options) => getStrategy(config).discoverVersions(config, options),
      upsertPackage,
      createSyncJob,
      updateSyncJob,
      incrementJobCounters,
      insertVersion,
      insertArtifact,
      updateArtifactStatus,
      downloadArtifact: (req, dryRun) => this.downloadService.downloadArtifact(req, dryRun),
      enforceRetention: (packageName, keep, dryRun, groupsToKeep) =>
        this.retentionService.enforceRetention(packageName, keep, dryRun, groupsToKeep),
      getMaxAvailableVersionSort,
      ...opts.deps,
    };
  }

  async run(options: SyncRunOptions = {}): Promise<SyncRunResult> {
    const dryRun = options.dryRun ?? false;

    if (dryRun) {
      const allDiscovered = await this.deps.discoverVersions(this.packageConfig, options.discovery);
      const discovered = options.discovery?.historical
        ? allDiscovered
        : this.applyRetentionWindow(allDiscovered);
      const artifactsQueued = discovered.reduce((sum, v) => sum + v.artifacts.size, 0);
      return {
        dryRun: true,
        versionsFound: discovered.length,
        artifactsQueued,
        downloaded: 0,
        failed: 0,
        retention: { versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] },
      };
    }

    return this.withLock(async () => {
      const job = await this._setupJob(options);
      return this._doSync(job, options);
    });
  }

  /**
   * Hold the package's sync lock for the whole run. The lock is a session advisory lock, so
   * a crashed process releases it rather than stranding the next scheduled run.
   */
  private async withLock<T>(fn: () => Promise<T>): Promise<T> {
    const key = this.packageConfig.name;
    try {
      return await withAdvisoryLock(this.pool, SYNC_LOCK_NAMESPACE, key, fn);
    } catch (err) {
      if (
        err instanceof AdvisoryLockUnavailableError &&
        err.namespace === SYNC_LOCK_NAMESPACE &&
        err.key === key
      ) {
        throw new SyncAlreadyRunningError(key);
      }
      throw err;
    }
  }

  async startAsync(options: SyncRunOptions = {}): Promise<number> {
    const job = await this._setupJob(options);
    // The lock is taken *inside* the detached chain so it is held for the whole background
    // run, not just until this function returns. Contention marks the job failed with a
    // clear reason rather than silently running a second, racing sync.
    this.withLock(() => this._doSync(job, options)).catch(async (err) => {
      log.error({ jobId: job.id, err }, "Background sync crashed");
      await this.deps
        .updateSyncJob(this.pool, job.id, {
          status: "failed",
          error_message: err instanceof Error ? err.message : String(err),
          completed_at: new Date(),
        })
        .catch(() => {});
    });
    return job.id;
  }

  private async _setupJob(options: SyncRunOptions): Promise<SyncJobRow> {
    const triggerType = options.triggerType ?? "scheduled";
    const configHash = hashConfig(this.packageConfig);
    await this.deps.upsertPackage(this.pool, {
      name: this.packageConfig.name,
      display_name: this.packageConfig.display_name,
      vendor: this.packageConfig.vendor,
      description: this.packageConfig.description ?? null,
      website: this.packageConfig.website ?? null,
      config_hash: configHash,
      enabled: true,
    });
    return this.deps.createSyncJob(this.pool, this.packageConfig.name, triggerType);
  }

  private async _doSync(job: SyncJobRow, options: SyncRunOptions): Promise<SyncRunResult> {
    const triggerType = options.triggerType ?? "scheduled";
    try {
      log.info(
        {
          package: this.packageConfig.name,
          triggerType,
          syncConcurrency: this.syncConcurrency,
          downloadConcurrency: this.downloadConcurrency,
        },
        "Starting package sync",
      );

      // Capture the highest version already available in storage before we insert anything.
      // Versions strictly above this threshold are treated as newly released and subject to
      // cooling off. Null means no baseline exists yet (bootstrap), so nothing is cooled off.
      const coolingOffThreshold = await this.deps.getMaxAvailableVersionSort(
        this.pool,
        this.packageConfig.name,
      );

      const allDiscovered = await this.deps.discoverVersions(this.packageConfig, options.discovery);
      const aboveMin = this.applyMinVersion(allDiscovered);
      const discovered = options.discovery?.historical
        ? aboveMin
        : this.applyRetentionWindow(aboveMin, coolingOffThreshold);
      await this.deps.updateSyncJob(this.pool, job.id, {
        versions_found: discovered.length,
      });
      log.info(
        {
          package: this.packageConfig.name,
          jobId: job.id,
          versionsDiscovered: allDiscovered.length,
          versionsBelowMin: allDiscovered.length - aboveMin.length,
          versionsInWindow: discovered.length,
          versionsSkipped: aboveMin.length - discovered.length,
        },
        "Discovery complete",
      );

      const queued: DownloadRequest[] = [];

      await mapWithConcurrency(discovered, this.syncConcurrency, async (version) => {
        await this.processVersion(version, queued, job.id, coolingOffThreshold);
      });

      await this.deps.updateSyncJob(this.pool, job.id, {
        versions_found: discovered.length,
        artifacts_queued: queued.length,
      });
      log.info(
        {
          package: this.packageConfig.name,
          jobId: job.id,
          artifactsQueued: queued.length,
        },
        "Artifact queue prepared",
      );

      let completedDownloads = 0;
      const downloadResults = await mapWithConcurrency(
        queued,
        this.downloadConcurrency,
        async (request) => {
          const result = await this.deps.downloadArtifact(request, false);
          completedDownloads += 1;

          if (result.status === "failed") {
            log.warn(
              {
                package: this.packageConfig.name,
                jobId: job.id,
                url: request.upstreamUrl,
                error: result.error,
              },
              "Artifact download failed",
            );
            await this.deps
              .incrementJobCounters(this.pool, job.id, { failed: 1 })
              .catch((err) =>
                log.warn({ jobId: job.id, err }, "Failed to increment job failed counter"),
              );
          } else {
            if (
              completedDownloads === 1 ||
              completedDownloads % 10 === 0 ||
              completedDownloads === queued.length
            ) {
              log.info(
                {
                  package: this.packageConfig.name,
                  jobId: job.id,
                  completedDownloads,
                  totalDownloads: queued.length,
                  latestStatus: result.status,
                },
                "Download progress",
              );
            }
            await this.deps
              .incrementJobCounters(this.pool, job.id, { downloaded: 1 })
              .catch((err) =>
                log.warn({ jobId: job.id, err }, "Failed to increment job downloaded counter"),
              );
          }

          return result;
        },
      );

      const downloaded = downloadResults.filter((r) => r.status === "available").length;
      const failed = downloadResults.filter((r) => r.status === "failed").length;

      const retention = await this.deps.enforceRetention(
        this.packageConfig.name,
        this.packageConfig.retention.versions_per_group,
        false,
        this.packageConfig.retention.groups_to_keep,
      );

      await this.deps.updateSyncJob(this.pool, job.id, {
        status: failed > 0 ? "failed" : "completed",
        versions_found: discovered.length,
        artifacts_queued: queued.length,
        error_message: failed > 0 ? `${failed} download(s) failed` : null,
        completed_at: new Date(),
      });
      log.info(
        {
          package: this.packageConfig.name,
          jobId: job.id,
          versionsFound: discovered.length,
          artifactsQueued: queued.length,
          downloaded,
          failed,
          retention,
        },
        "Package sync completed",
      );

      return {
        dryRun: false,
        jobId: job.id,
        versionsFound: discovered.length,
        artifactsQueued: queued.length,
        downloaded,
        failed,
        retention,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.deps.updateSyncJob(this.pool, job.id, {
        status: "failed",
        error_message: message,
        completed_at: new Date(),
      });
      log.error(
        {
          package: this.packageConfig.name,
          jobId: job.id,
          error: message,
        },
        "Package sync failed",
      );
      throw err;
    }
  }

  private applyMinVersion(versions: DiscoveredVersion[]): DiscoveredVersion[] {
    const { min_version: minVersion } = this.packageConfig.versioning;
    if (!minVersion) return versions;
    const minKey = generateSortKey(minVersion);
    return versions.filter((v) => generateSortKey(v.version) >= minKey);
  }

  private applyRetentionWindow(
    versions: DiscoveredVersion[],
    coolingOffThreshold: string | null = null,
  ): DiscoveredVersion[] {
    return selectRetentionWindow(versions, this.packageConfig.retention, coolingOffThreshold);
  }

  private async processVersion(
    version: DiscoveredVersion,
    queued: DownloadRequest[],
    jobId: number,
    coolingOffThreshold: string | null,
  ): Promise<void> {
    const versionRow = await this.deps.insertVersion(this.pool, {
      package_name: this.packageConfig.name,
      version: version.version,
      version_group: version.versionGroup,
      is_lts: version.isLts,
      version_sort: generateSortKey(version.version),
    });

    // versionRow.discovered_at, not the clock: this is the one call site whose result is persisted,
    // and it is recomputed on every sync for as long as the artifact stays pending (WAL-91).
    const coolingOffUntil = computeCoolingOffUntil(
      version,
      this.packageConfig.retention,
      coolingOffThreshold,
      versionRow.discovered_at,
    );

    for (const [platform, artifact] of version.artifacts) {
      const [os, arch] = platform.split("/");
      if (!os || !arch) {
        continue;
      }
      // A transform changes what walrus serves: the row's filename and storage path describe
      // the transformed output, while upstream_url below keeps pointing at the source bytes.
      const platformConfig = this.packageConfig.platforms.find(
        (p) => p.os === os && p.arch === arch,
      );
      const filename = platformConfig?.transform
        ? renderServedFilename(
            platformConfig.transform,
            platformConfig,
            version.version,
            artifact.filename,
          )
        : artifact.filename;
      const artifactRow = await this.deps.insertArtifact(this.pool, {
        version_id: versionRow.id,
        os,
        arch,
        filename,
        upstream_url: artifact.url,
        sync_job_id: jobId,
        cooling_off_until: coolingOffUntil,
      });

      // Record what *discovery* learned, and only that (WAL-102).
      //
      // Two rules, both learned the hard way. First, `artifacts.checksum` describes the bytes
      // walrus has stored, so once an artifact is available its digest is a fact about those
      // bytes and discovery has nothing to say about it — re-running discovery must not touch
      // it. Second, a field discovery did not resolve must be left alone rather than written
      // as NULL: for a package whose config gives a checksum *URL* rather than a value, the
      // digest is not known until `DownloadService` fetches it, and `checksum ?? null` here
      // erased the stored digest of an already-cached artifact on every subsequent sync. It
      // could not self-heal, because an available artifact is never queued for download.
      if (artifactRow.status !== "available") {
        const discovered: Parameters<typeof updateArtifactStatus>[2] = {
          status: artifactRow.status,
        };
        if (artifact.checksum) discovered.checksum = artifact.checksum;
        const checksumType = normalizeChecksumType(artifact.checksumType);
        if (checksumType) discovered.checksum_type = checksumType;

        // `updateArtifactStatus` only writes the keys present on the update, so an omitted
        // field keeps whatever the column already holds.
        if (discovered.checksum !== undefined || discovered.checksum_type !== undefined) {
          await this.deps.updateArtifactStatus(this.pool, artifactRow.id, discovered);
        }
      }

      // An artifact that is serving but carries no digest is the residue of WAL-102: its
      // checksum was erased by a discovery-time write and cannot be recovered in place,
      // because the digest describes the stored bytes and only a download recomputes it.
      // Re-fetching also re-verifies against upstream on the way through, which is the
      // stronger of the two repairs available (PO decision, 2026-08-31) — the alternative,
      // hashing whatever is already in the bucket, would bless bytes that have been served
      // without a published digest rather than check them.
      //
      // `checksum_type IS NOT NULL` keeps this to artifacts that are *meant* to have a digest,
      // so a package deliberately configured without checksums is not re-fetched forever.
      // Self-healing rather than a migration: it repairs the estate on the next sync and stays
      // correct if the state ever reappears.
      const missingChecksum =
        artifactRow.status === "available" &&
        artifactRow.checksum === null &&
        artifactRow.checksum_type !== null;

      // The same defect's other face, and the worse of the two. Where discovery supplies a
      // checksum *value* rather than a URL, the old write did not null the digest — it replaced
      // it with **upstream's**. For an untransformed artifact those are the same number and
      // nothing is visibly wrong. For a transformed one the served bytes are walrus's own, so
      // the published digest becomes a digest of bytes walrus does not serve, and every client
      // that verifies its download fails on a good file. A null digest is at least honest;
      // this one lies. `checksum === source_checksum` on a transformed artifact is exactly that
      // state — WAL-58's provenance split means they must differ.
      const upstreamDigestOverwroteServed =
        artifactRow.status === "available" &&
        artifactRow.transform !== null &&
        artifactRow.source_checksum !== null &&
        artifactRow.checksum === artifactRow.source_checksum;

      const needsChecksumRepair = missingChecksum || upstreamDigestOverwroteServed;

      if (needsChecksumRepair) {
        log.warn(
          {
            package: this.packageConfig.name,
            artifactId: artifactRow.id,
            version: version.version,
            reason: missingChecksum
              ? "no stored checksum"
              : "served digest overwritten by upstream's",
          },
          "Artifact digest does not describe the bytes served; re-downloading to repair it",
        );
      }

      if (artifactRow.status === "pending" || needsChecksumRepair) {
        if (artifactRow.cooling_off_until !== null && artifactRow.cooling_off_until > new Date()) {
          continue; // still in cooling off period — leave as pending, download on next sync
        }
        queued.push({
          artifactId: artifactRow.id,
          upstreamUrl: artifact.url,
          storagePath: buildArtifactPath({
            packageName: this.packageConfig.name,
            version: version.version,
            os,
            arch,
            filename,
          }),
          expectedChecksum: artifact.checksum,
          checksumUrl: artifact.checksumUrl,
          checksumType: normalizeChecksumType(artifact.checksumType),
          expectedSize: artifact.size,
          transform: platformConfig?.transform,
        });
      }
    }
  }
}

function hashConfig(config: PackageConfig): string {
  return crypto.createHash("sha256").update(JSON.stringify(config)).digest("hex");
}

function normalizeChecksumType(type?: string): "sha256" | "sha1" | undefined {
  if (!type) return undefined;
  if (type === "sha1" || type === "sha256") return type;
  return undefined;
}
