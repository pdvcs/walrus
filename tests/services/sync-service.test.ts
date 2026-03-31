import { describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { DiscoveredVersion } from "../../src/discovery/types.js";
import { SyncService } from "../../src/services/sync-service.js";
import { PackageConfig } from "../../src/types/package-config.js";
import { DownloadService } from "../../src/services/download-service.js";
import { RetentionService } from "../../src/services/retention-service.js";

const pkg: PackageConfig = {
  name: "uv",
  display_name: "uv",
  vendor: "Astral",
  website: "https://example.test",
  description: "test",
  discovery: {
    type: "github-releases",
    repo: "astral-sh/uv",
    include_prereleases: false,
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    lts_support: false,
    lts_source: "none",
  },
  retention: {
    versions_per_group: 2,
  },
  checksum: {
    type: "none",
    algorithm: "sha256",
  },
  platforms: [
    {
      os: "linux",
      arch: "x86-64",
      os_upstream: "linux",
      arch_upstream: "x86_64",
      extension: "tar.gz",
    },
  ],
};

function discovered(version: string, group?: string, releasedAt?: Date): DiscoveredVersion {
  const versionGroup = group ?? version.split(".").slice(0, 2).join(".");
  return {
    version,
    versionGroup,
    isLts: false,
    releasedAt,
    artifacts: new Map([
      [
        "linux/x86-64",
        {
          url: `https://example.test/${version}/uv.tar.gz`,
          filename: "uv.tar.gz",
          checksum: undefined,
          checksumType: "sha256",
        },
      ],
    ]),
  };
}

describe("SyncService", () => {
  it("runs discovery, queues downloads, updates job, and enforces retention", async () => {
    const downloadService = {
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
    } as unknown as DownloadService;

    const retentionService = {
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 1, artifactsDeleted: 1, versionIdsPruned: [7] }),
    } as unknown as RetentionService;

    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([discovered("0.6.2"), discovered("0.6.1")]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 100 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValueOnce({ id: 1 }).mockResolvedValueOnce({ id: 2 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({ id: 10, status: "pending", cooling_off_until: null })
        .mockResolvedValueOnce({ id: 11, status: "pending", cooling_off_until: null }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 1, artifactsDeleted: 1, versionIdsPruned: [7] }),
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(null),
    };

    const service = new SyncService({} as Pool, pkg, downloadService, retentionService, {
      deps,
      syncConcurrency: 2,
      downloadConcurrency: 2,
    });

    const result = await service.run({ triggerType: "admin" });

    expect(result.versionsFound).toBe(2);
    expect(result.artifactsQueued).toBe(2);
    expect(result.downloaded).toBe(2);
    expect(result.failed).toBe(0);
    expect(deps.createSyncJob).toHaveBeenCalledOnce();
    expect(deps.insertVersion).toHaveBeenCalledTimes(2);
    expect(deps.insertArtifact).toHaveBeenCalledTimes(2);
    expect(deps.downloadArtifact).toHaveBeenCalledTimes(2);
    expect(deps.enforceRetention).toHaveBeenCalledWith("uv", 2, false, undefined);
    expect(deps.updateSyncJob).toHaveBeenCalled();
  });

  it("respects configured download concurrency", async () => {
    let active = 0;
    let maxActive = 0;

    const deps = {
      discoverVersions: vi
        .fn()
        .mockResolvedValue([
          discovered("0.9.1"),
          discovered("0.8.1"),
          discovered("0.7.1"),
          discovered("0.6.1"),
        ]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 101 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi
        .fn()
        .mockResolvedValueOnce({ id: 1 })
        .mockResolvedValueOnce({ id: 2 })
        .mockResolvedValueOnce({ id: 3 })
        .mockResolvedValueOnce({ id: 4 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({ id: 11, status: "pending", cooling_off_until: null })
        .mockResolvedValueOnce({ id: 12, status: "pending", cooling_off_until: null })
        .mockResolvedValueOnce({ id: 13, status: "pending", cooling_off_until: null })
        .mockResolvedValueOnce({ id: 14, status: "pending", cooling_off_until: null }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockImplementation(async () => {
        active += 1;
        maxActive = Math.max(maxActive, active);
        await new Promise((resolve) => setTimeout(resolve, 25));
        active -= 1;
        return { status: "available", attempts: 1 };
      }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(null),
    };

    const service = new SyncService(
      {} as Pool,
      pkg,
      {} as DownloadService,
      {} as RetentionService,
      {
        deps,
        syncConcurrency: 4,
        downloadConcurrency: 2,
      },
    );

    await service.run();

    expect(maxActive).toBeLessThanOrEqual(2);
  });

  it("pre-filters discovered versions to the retention window before downloading", async () => {
    const pkgWithGroups: PackageConfig = {
      ...pkg,
      retention: { versions_per_group: 2, groups_to_keep: 2 },
    };

    // 3 groups × 3 versions = 9 total; window is 2 groups × 2 versions = 4
    const deps = {
      discoverVersions: vi
        .fn()
        .mockResolvedValue([
          discovered("0.8.3"),
          discovered("0.8.2"),
          discovered("0.8.1"),
          discovered("0.7.2"),
          discovered("0.7.1"),
          discovered("0.7.0"),
          discovered("0.6.2"),
          discovered("0.6.1"),
          discovered("0.6.0"),
        ]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 200 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValue({ id: 1 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValue({ id: 1, status: "pending", cooling_off_until: null }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(null),
    };

    const service = new SyncService(
      {} as Pool,
      pkgWithGroups,
      {} as DownloadService,
      {} as RetentionService,
      { deps },
    );

    const result = await service.run();

    // Only 4 versions processed, not 9
    expect(result.versionsFound).toBe(4);
    expect(deps.insertVersion).toHaveBeenCalledTimes(4);

    // Newest 2 versions of newest 2 groups inserted
    const insertedVersions = vi
      .mocked(deps.insertVersion)
      .mock.calls.map((call) => (call[1] as { version: string }).version);
    expect(insertedVersions).toContain("0.8.3");
    expect(insertedVersions).toContain("0.8.2");
    expect(insertedVersions).toContain("0.7.2");
    expect(insertedVersions).toContain("0.7.1");
    expect(insertedVersions).not.toContain("0.8.1");
    expect(insertedVersions).not.toContain("0.6.2");
  });

  it("skips binary download for artifacts within the cooling off window", async () => {
    const pkgWithCoolingOff: PackageConfig = {
      ...pkg,
      retention: { versions_per_group: 2, cooling_off_days: 3 },
    };

    // Threshold = 0.10.9's sort key — meaning 0.10.9 is already available,
    // so only 0.10.10 (strictly above threshold) is subject to cooling off.
    // generateSortKey uses 6-digit padding + "~" suffix for stable releases.
    const thresholdSort = "000000.000010.000009~"; // generateSortKey("0.10.9")
    const coolingOffUntil = new Date(Date.now() + 3 * 86_400_000); // 3 days from now

    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([
        discovered("0.10.10"), // new — above threshold, within cooling off window
        discovered("0.10.9"), // already available — at threshold, not cooled off
      ]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 300 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValueOnce({ id: 1 }).mockResolvedValueOnce({ id: 2 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({ id: 20, status: "pending", cooling_off_until: coolingOffUntil }) // 0.10.10 — in cooling off
        .mockResolvedValueOnce({ id: 21, status: "pending", cooling_off_until: null }), // 0.10.9 — no cooling off
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(thresholdSort),
    };

    const service = new SyncService(
      {} as Pool,
      pkgWithCoolingOff,
      {} as DownloadService,
      {} as RetentionService,
      { deps },
    );

    const result = await service.run({ triggerType: "scheduled" });

    // Both versions discovered, but only one artifact queued/downloaded
    expect(result.versionsFound).toBe(2);
    expect(result.artifactsQueued).toBe(1);
    expect(result.downloaded).toBe(1);
    expect(deps.downloadArtifact).toHaveBeenCalledTimes(1);
    // The download that happened should be for the older artifact (id 21)
    expect(deps.downloadArtifact).toHaveBeenCalledWith(
      expect.objectContaining({ artifactId: 21 }),
      false,
    );
  });

  it("does not apply cooling off when threshold is null (bootstrap: no available artifacts yet)", async () => {
    const pkgWithCoolingOff: PackageConfig = {
      ...pkg,
      retention: { versions_per_group: 2, cooling_off_days: 3 },
    };

    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([discovered("0.1.0"), discovered("0.1.1")]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 400 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValueOnce({ id: 1 }).mockResolvedValueOnce({ id: 2 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({ id: 30, status: "pending", cooling_off_until: null })
        .mockResolvedValueOnce({ id: 31, status: "pending", cooling_off_until: null }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      // null threshold = no available artifacts yet (bootstrap)
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(null),
    };

    const service = new SyncService(
      {} as Pool,
      pkgWithCoolingOff,
      {} as DownloadService,
      {} as RetentionService,
      { deps },
    );

    const result = await service.run({ triggerType: "scheduled" });

    // All artifacts downloaded despite being within cooling_off_days, because threshold is null
    expect(result.downloaded).toBe(2);
    expect(deps.downloadArtifact).toHaveBeenCalledTimes(2);
  });

  it("does not apply cooling off to versions at or below the threshold", async () => {
    const pkgWithCoolingOff: PackageConfig = {
      ...pkg,
      retention: { versions_per_group: 2, cooling_off_days: 3 },
    };

    // Threshold is 0.10.9's sort key — 0.10.9 is at the threshold (not above it)
    const thresholdSort = "000000.000010.000009~";

    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([discovered("0.10.9")]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 500 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValueOnce({ id: 1 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({ id: 40, status: "pending", cooling_off_until: null }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(thresholdSort),
    };

    const service = new SyncService(
      {} as Pool,
      pkgWithCoolingOff,
      {} as DownloadService,
      {} as RetentionService,
      { deps },
    );

    const result = await service.run({ triggerType: "scheduled" });

    // 0.10.9 is exactly at the threshold — not strictly above, so not cooled off
    expect(result.downloaded).toBe(1);
    expect(deps.downloadArtifact).toHaveBeenCalledTimes(1);
  });

  it("downloads a version above the threshold once the cooling off window has passed", async () => {
    const pkgWithCoolingOff: PackageConfig = {
      ...pkg,
      retention: { versions_per_group: 2, cooling_off_days: 3 },
    };

    const thresholdSort = "000000.000010.000009~";
    // cooling_off_until is 1 day in the past — window has elapsed
    const pastCoolingOff = new Date(Date.now() - 86_400_000);

    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([discovered("0.10.10")]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 600 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValueOnce({ id: 1 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({ id: 50, status: "pending", cooling_off_until: pastCoolingOff }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(thresholdSort),
    };

    const service = new SyncService(
      {} as Pool,
      pkgWithCoolingOff,
      {} as DownloadService,
      {} as RetentionService,
      { deps },
    );

    const result = await service.run({ triggerType: "scheduled" });

    // 0.10.10 is above the threshold but the cooling off window has elapsed — should download
    expect(result.downloaded).toBe(1);
    expect(deps.downloadArtifact).toHaveBeenCalledTimes(1);
  });

  it("applies cooling off on bootstrap when releasedAt is available and recent", async () => {
    const pkgWithCoolingOff: PackageConfig = {
      ...pkg,
      retention: { versions_per_group: 2, cooling_off_days: 3 },
    };

    const sixHoursAgo = new Date(Date.now() - 6 * 3600_000);
    const fourDaysAgo = new Date(Date.now() - 4 * 86_400_000);

    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([
        discovered("0.10.10", undefined, sixHoursAgo), // released 6h ago — within 3-day cooling off
        discovered("0.10.9", undefined, fourDaysAgo), // released 4 days ago — cooling off elapsed
      ]),
      upsertPackage: vi.fn().mockResolvedValue({}),
      createSyncJob: vi.fn().mockResolvedValue({ id: 700 }),
      updateSyncJob: vi.fn().mockResolvedValue({}),
      insertVersion: vi.fn().mockResolvedValueOnce({ id: 1 }).mockResolvedValueOnce({ id: 2 }),
      insertArtifact: vi
        .fn()
        .mockResolvedValueOnce({
          id: 60,
          status: "pending",
          cooling_off_until: new Date(Date.now() + 3 * 86_400_000 - 6 * 3600_000),
        })
        .mockResolvedValueOnce({ id: 61, status: "pending", cooling_off_until: null }),
      updateArtifactStatus: vi.fn().mockResolvedValue({}),
      incrementJobCounters: vi.fn().mockResolvedValue(undefined),
      downloadArtifact: vi.fn().mockResolvedValue({ status: "available", attempts: 1 }),
      enforceRetention: vi
        .fn()
        .mockResolvedValue({ versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] }),
      // null threshold = bootstrap
      getMaxAvailableVersionSort: vi.fn().mockResolvedValue(null),
    };

    const service = new SyncService(
      {} as Pool,
      pkgWithCoolingOff,
      {} as DownloadService,
      {} as RetentionService,
      { deps },
    );

    const result = await service.run({ triggerType: "scheduled" });

    // 0.10.10 (released 6h ago) blocked; 0.10.9 (released 4 days ago) downloaded
    expect(result.artifactsQueued).toBe(1);
    expect(result.downloaded).toBe(1);
    expect(deps.downloadArtifact).toHaveBeenCalledTimes(1);
    expect(deps.downloadArtifact).toHaveBeenCalledWith(
      expect.objectContaining({ artifactId: 61 }),
      false,
    );
    // Verify cooling_off_until was passed to insertArtifact for the recent version
    const firstInsertCall = vi.mocked(deps.insertArtifact).mock.calls[0][1] as {
      cooling_off_until: Date | null;
    };
    expect(firstInsertCall.cooling_off_until).not.toBeNull();
    const secondInsertCall = vi.mocked(deps.insertArtifact).mock.calls[1][1] as {
      cooling_off_until: Date | null;
    };
    expect(secondInsertCall.cooling_off_until).toBeNull();
  });

  it("supports dry-run mode without DB writes or downloads", async () => {
    const deps = {
      discoverVersions: vi.fn().mockResolvedValue([discovered("0.6.2"), discovered("0.6.1")]),
      upsertPackage: vi.fn(),
      createSyncJob: vi.fn(),
      updateSyncJob: vi.fn(),
      insertVersion: vi.fn(),
      insertArtifact: vi.fn(),
      updateArtifactStatus: vi.fn(),
      downloadArtifact: vi.fn(),
      enforceRetention: vi.fn(),
    };

    const service = new SyncService(
      {} as Pool,
      pkg,
      {} as DownloadService,
      {} as RetentionService,
      {
        deps,
      },
    );

    const result = await service.run({ dryRun: true, triggerType: "admin" });

    expect(result.dryRun).toBe(true);
    expect(result.versionsFound).toBe(2);
    expect(result.artifactsQueued).toBe(2);
    expect(deps.upsertPackage).not.toHaveBeenCalled();
    expect(deps.createSyncJob).not.toHaveBeenCalled();
    expect(deps.downloadArtifact).not.toHaveBeenCalled();
  });
});
