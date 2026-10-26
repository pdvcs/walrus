import { Pool } from "pg";
import {
  listVersionGroups,
  listVersionIdsNewestPerPlatformInGroup,
  listVersionsOlderThanInGroup,
} from "../db/queries/versions.js";
import { listArtifactsForVersion } from "../db/queries/artifacts.js";
import { StorageBackend } from "../storage/types.js";
import { VersionRow } from "../types/db.js";

export interface RetentionServiceOptions {
  versionsRepo?: {
    listVersionGroups: typeof listVersionGroups;
    listVersionsOlderThanInGroup: typeof listVersionsOlderThanInGroup;
    listVersionIdsNewestPerPlatformInGroup?: typeof listVersionIdsNewestPerPlatformInGroup;
  };
  artifactsRepo?: {
    listArtifactsForVersion: typeof listArtifactsForVersion;
  };
}

export interface RetentionResult {
  versionsPruned: number;
  artifactsDeleted: number;
  versionIdsPruned: number[];
}

export class RetentionService {
  private readonly versionsRepo: NonNullable<RetentionServiceOptions["versionsRepo"]>;
  private readonly artifactsRepo: NonNullable<RetentionServiceOptions["artifactsRepo"]>;

  constructor(
    private readonly pool: Pool,
    private readonly storage: StorageBackend,
    opts: RetentionServiceOptions = {},
  ) {
    this.versionsRepo =
      opts.versionsRepo ??
      ({
        listVersionGroups,
        listVersionsOlderThanInGroup,
        listVersionIdsNewestPerPlatformInGroup,
      } as const);
    this.artifactsRepo =
      opts.artifactsRepo ??
      ({
        listArtifactsForVersion,
      } as const);
  }

  /**
   * Versions beyond the newest `keep` in a group, minus any that are still one of the newest
   * `keep` for some platform: upstream platform lag (Temurin Windows) would otherwise get the
   * only servable version for that platform pruned.
   */
  private async olderVersionsToPrune(
    packageName: string,
    group: string,
    keep: number,
  ): Promise<VersionRow[]> {
    const older = await this.versionsRepo.listVersionsOlderThanInGroup(
      this.pool,
      packageName,
      group,
      keep,
    );
    if (older.length === 0 || !this.versionsRepo.listVersionIdsNewestPerPlatformInGroup) {
      return older;
    }
    const protectedIds = new Set(
      await this.versionsRepo.listVersionIdsNewestPerPlatformInGroup(
        this.pool,
        packageName,
        group,
        keep,
      ),
    );
    return older.filter((v) => !protectedIds.has(v.id));
  }

  async enforceRetention(
    packageName: string,
    versionsPerGroup: number,
    dryRun = false,
    groupsToKeep?: number,
  ): Promise<RetentionResult> {
    const groups = await this.versionsRepo.listVersionGroups(this.pool, packageName);
    const prunable: VersionRow[] = [];

    if (groupsToKeep !== undefined) {
      const keptGroups = groups.slice(0, groupsToKeep);
      const droppedGroups = groups.slice(groupsToKeep);

      for (const group of droppedGroups) {
        // The whole group is going, so a live embargo earns no reprieve.
        const allVersions = await this.versionsRepo.listVersionsOlderThanInGroup(
          this.pool,
          packageName,
          group,
          0,
          false,
        );
        prunable.push(...allVersions);
      }

      for (const group of keptGroups) {
        prunable.push(...(await this.olderVersionsToPrune(packageName, group, versionsPerGroup)));
      }
    } else {
      for (const group of groups) {
        prunable.push(...(await this.olderVersionsToPrune(packageName, group, versionsPerGroup)));
      }
    }

    let artifactsDeleted = 0;

    for (const version of prunable) {
      const artifacts = await this.artifactsRepo.listArtifactsForVersion(this.pool, version.id);
      for (const artifact of artifacts) {
        if (!dryRun && artifact.gcs_path) {
          await this.storage.delete(artifact.gcs_path);
        }
        artifactsDeleted += 1;
      }

      if (!dryRun) {
        await this.pool.query("DELETE FROM versions WHERE id = $1", [version.id]);
      }
    }

    return {
      versionsPruned: prunable.length,
      artifactsDeleted,
      versionIdsPruned: prunable.map((v) => v.id),
    };
  }
}
