import { describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { RetentionService } from "../../src/services/retention-service.js";
import { StorageBackend } from "../../src/storage/types.js";
import { ArtifactRow, VersionRow } from "../../src/types/db.js";

function version(id: number, group: string, v: string): VersionRow {
  return {
    id,
    package_name: "uv",
    version: v,
    version_group: group,
    is_lts: false,
    discovered_at: new Date(),
    version_sort: v,
  };
}

function artifact(id: number, versionId: number, gcsPath: string | null): ArtifactRow {
  return {
    id,
    version_id: versionId,
    os: "linux",
    arch: "x86-64",
    filename: "uv.tar.gz",
    gcs_path: gcsPath,
    file_size: 100,
    checksum: null,
    checksum_type: null,
    upstream_url: "https://example.test/uv.tar.gz",
    status: "available",
    error_message: null,
    download_started_at: null,
    download_completed_at: null,
    removed_at: null,
    created_at: new Date(),
  };
}

describe("RetentionService", () => {
  it("prunes versions older than retention and deletes storage objects", async () => {
    const storage: StorageBackend = {
      upload: vi.fn(),
      download: vi.fn(),
      delete: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn(),
    };

    const pool = { query: vi.fn().mockResolvedValue(undefined) } as unknown as Pool;

    const service = new RetentionService(pool, storage, {
      versionsRepo: {
        listVersionGroups: vi.fn().mockResolvedValue(["1.2"]),
        listVersionsOlderThanInGroup: vi
          .fn()
          .mockResolvedValue([version(11, "1.2", "1.2.1"), version(12, "1.2", "1.2.0")]),
      },
      artifactsRepo: {
        listArtifactsForVersion: vi
          .fn()
          .mockResolvedValueOnce([artifact(1, 11, "uv/1.2.1/linux/x86-64/uv.tar.gz")])
          .mockResolvedValueOnce([artifact(2, 12, "uv/1.2.0/linux/x86-64/uv.tar.gz")]),
      },
    });

    const result = await service.enforceRetention("uv", 1);

    expect(result.versionsPruned).toBe(2);
    expect(result.artifactsDeleted).toBe(2);
    expect(vi.mocked(storage.delete)).toHaveBeenCalledTimes(2);
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(vi.mocked(pool.query)).toHaveBeenCalledTimes(2);
  });

  it("with groupsToKeep, drops all versions in older groups and trims newer groups", async () => {
    const storage: StorageBackend = {
      upload: vi.fn(),
      download: vi.fn(),
      delete: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn(),
    };

    const pool = { query: vi.fn().mockResolvedValue(undefined) } as unknown as Pool;

    // 5 groups (newest first): 0.10, 0.9, 0.8, 0.7, 0.6
    // groupsToKeep=3 → keep 0.10, 0.9, 0.8; drop 0.7 and 0.6 entirely
    // versionsPerGroup=2 → in kept groups, trim to 2 newest
    const listVersionsOlderThanInGroup = vi
      .fn()
      // 0.7 (dropped group, offset=0): returns all 3
      .mockResolvedValueOnce([
        version(70, "0.7", "0.7.2"),
        version(71, "0.7", "0.7.1"),
        version(72, "0.7", "0.7.0"),
      ])
      // 0.6 (dropped group, offset=0): returns all 2
      .mockResolvedValueOnce([version(60, "0.6", "0.6.1"), version(61, "0.6", "0.6.0")])
      // 0.10 (kept group, offset=2): returns 1 excess
      .mockResolvedValueOnce([version(100, "0.10", "0.10.0")])
      // 0.9 (kept group, offset=2): nothing to prune
      .mockResolvedValueOnce([])
      // 0.8 (kept group, offset=2): nothing to prune
      .mockResolvedValueOnce([]);

    const service = new RetentionService(pool, storage, {
      versionsRepo: {
        listVersionGroups: vi.fn().mockResolvedValue(["0.10", "0.9", "0.8", "0.7", "0.6"]),
        listVersionsOlderThanInGroup,
      },
      artifactsRepo: {
        listArtifactsForVersion: vi.fn().mockResolvedValue([]),
      },
    });

    const result = await service.enforceRetention("uv", 2, false, 3);

    expect(result.versionsPruned).toBe(6); // 3 + 2 + 1
    // Dropped groups called with offset=0; kept groups called with offset=versionsPerGroup
    expect(listVersionsOlderThanInGroup).toHaveBeenNthCalledWith(1, pool, "uv", "0.7", 0);
    expect(listVersionsOlderThanInGroup).toHaveBeenNthCalledWith(2, pool, "uv", "0.6", 0);
    expect(listVersionsOlderThanInGroup).toHaveBeenNthCalledWith(3, pool, "uv", "0.10", 2);
  });

  it("without groupsToKeep, behaves as before (all groups trimmed to versionsPerGroup)", async () => {
    const storage: StorageBackend = {
      upload: vi.fn(),
      download: vi.fn(),
      delete: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn(),
    };

    const pool = { query: vi.fn().mockResolvedValue(undefined) } as unknown as Pool;

    const listVersionsOlderThanInGroup = vi
      .fn()
      .mockResolvedValueOnce([version(10, "0.10", "0.10.0")])
      .mockResolvedValueOnce([version(90, "0.9", "0.9.0")]);

    const service = new RetentionService(pool, storage, {
      versionsRepo: {
        listVersionGroups: vi.fn().mockResolvedValue(["0.10", "0.9"]),
        listVersionsOlderThanInGroup,
      },
      artifactsRepo: {
        listArtifactsForVersion: vi.fn().mockResolvedValue([]),
      },
    });

    const result = await service.enforceRetention("uv", 3);

    expect(result.versionsPruned).toBe(2);
    expect(listVersionsOlderThanInGroup).toHaveBeenNthCalledWith(1, pool, "uv", "0.10", 3);
    expect(listVersionsOlderThanInGroup).toHaveBeenNthCalledWith(2, pool, "uv", "0.9", 3);
  });

  it("supports dry-run mode with no deletes", async () => {
    const storage: StorageBackend = {
      upload: vi.fn(),
      download: vi.fn(),
      delete: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn(),
    };

    const pool = { query: vi.fn().mockResolvedValue(undefined) } as unknown as Pool;

    const service = new RetentionService(pool, storage, {
      versionsRepo: {
        listVersionGroups: vi.fn().mockResolvedValue(["1.2"]),
        listVersionsOlderThanInGroup: vi.fn().mockResolvedValue([version(11, "1.2", "1.2.1")]),
      },
      artifactsRepo: {
        listArtifactsForVersion: vi
          .fn()
          .mockResolvedValue([artifact(1, 11, "uv/1.2.1/linux/x86-64/uv.tar.gz")]),
      },
    });

    const result = await service.enforceRetention("uv", 1, true);

    expect(result.versionsPruned).toBe(1);
    expect(vi.mocked(storage.delete)).not.toHaveBeenCalled();
    // eslint-disable-next-line @typescript-eslint/unbound-method
    expect(vi.mocked(pool.query)).not.toHaveBeenCalled();
  });
});
