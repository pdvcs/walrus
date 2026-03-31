import { Pool } from "pg";
import { listVersionGroups, listVersionsOlderThanInGroup } from "../db/queries/versions.js";
import { listArtifactsForVersion } from "../db/queries/artifacts.js";
import { StorageBackend } from "../storage/types.js";
import { VersionRow } from "../types/db.js";

export interface RetentionServiceOptions {
  versionsRepo?: {
    listVersionGroups: typeof listVersionGroups;
    listVersionsOlderThanInGroup: typeof listVersionsOlderThanInGroup;
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
      } as const);
    this.artifactsRepo =
      opts.artifactsRepo ??
      ({
        listArtifactsForVersion,
      } as const);
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
        const allVersions = await this.versionsRepo.listVersionsOlderThanInGroup(
          this.pool,
          packageName,
          group,
          0,
        );
        prunable.push(...allVersions);
      }

      for (const group of keptGroups) {
        const oldVersions = await this.versionsRepo.listVersionsOlderThanInGroup(
          this.pool,
          packageName,
          group,
          versionsPerGroup,
        );
        prunable.push(...oldVersions);
      }
    } else {
      for (const group of groups) {
        const oldVersions = await this.versionsRepo.listVersionsOlderThanInGroup(
          this.pool,
          packageName,
          group,
          versionsPerGroup,
        );
        prunable.push(...oldVersions);
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
