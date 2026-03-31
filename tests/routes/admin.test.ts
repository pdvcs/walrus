import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAdminRouter, AdminRouteDeps } from "../../src/routes/admin.js";

function createTestApp(deps: Parameters<typeof createAdminRouter>[0]): express.Express {
  const app = express();
  app.use(express.json());
  app.use("/admin/v1", createAdminRouter(deps));
  return app;
}

function baseDeps(): AdminRouteDeps {
  return {
    listConfiguredPackages: vi.fn().mockReturnValue([]),
    getConfiguredPackageMeta: vi.fn().mockReturnValue([]),
    runSync: vi.fn(),
    runSyncAll: vi.fn(),
    startSyncAsync: vi.fn().mockResolvedValue(1),
    getArtifactByPackageVersionPlatform: vi.fn().mockResolvedValue(null),
    redownloadArtifact: vi.fn(),
    listArtifactsByPackageVersion: vi.fn().mockResolvedValue([]),
    removeArtifact: vi.fn(),
    listFailedArtifacts: vi.fn().mockResolvedValue([]),
    listPendingArtifacts: vi.fn().mockResolvedValue([]),
    listJobs: vi.fn().mockResolvedValue([]),
    getJob: vi.fn().mockResolvedValue(null),
    setPackageEnabled: vi.fn().mockResolvedValue(false),
    removeVersionGroup: vi.fn().mockResolvedValue({ versions: 0, artifacts: 0 }),
    removeAllVersionGroups: vi.fn().mockResolvedValue({ versions: 0, artifacts: 0 }),
    isPackageEnabled: vi.fn().mockResolvedValue(null),
    listAllPackages: vi.fn().mockResolvedValue([]),
    listVersionGroupNamesForPackage: vi.fn().mockResolvedValue([]),
    listVersionsInGroup: vi.fn().mockResolvedValue([]),
    listArtifactsForVersionId: vi.fn().mockResolvedValue([]),
    getTomlSource: vi.fn().mockReturnValue(null),
  };
}

describe("admin routes", () => {
  it("runs package sync in dry-run mode", async () => {
    const runSync = vi.fn().mockResolvedValue({
      dryRun: true,
      versionsFound: 3,
      artifactsQueued: 8,
      downloaded: 0,
      failed: 0,
      retention: { versionsPruned: 0, artifactsDeleted: 0, versionIdsPruned: [] },
    });

    const deps = baseDeps();
    deps.listConfiguredPackages = vi.fn().mockReturnValue(["uv"]);
    deps.runSync = runSync;
    const app = createTestApp(deps);

    const response = await request(app).post("/admin/v1/sync/uv?dry_run=true");
    const body = response.body as { dry_run: boolean };

    expect(response.status).toBe(200);
    expect(body.dry_run).toBe(true);
    expect(runSync).toHaveBeenCalledWith("uv", { dryRun: true, triggerType: "admin" });
  });

  it("redownloads a specific artifact", async () => {
    const deps = baseDeps();
    deps.listConfiguredPackages = vi.fn().mockReturnValue(["uv"]);
    deps.getArtifactByPackageVersionPlatform = vi.fn().mockResolvedValue({
      version: "0.6.2",
      artifact: {
        id: 77,
        version_id: 1,
        os: "linux",
        arch: "x86-64",
        filename: "uv.tar.gz",
        gcs_path: "uv/0.6.2/linux/x86-64/uv.tar.gz",
        file_size: 123,
        checksum: null,
        checksum_type: null,
        upstream_url: "https://example.test/uv.tar.gz",
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
      },
    });
    deps.redownloadArtifact = vi.fn().mockResolvedValue({ status: "available", attempts: 1 });
    const app = createTestApp(deps);

    const response = await request(app).post("/admin/v1/redownload/uv/0.6.2/linux/x86-64");
    const body = response.body as { artifact_id: number };

    expect(response.status).toBe(202);
    expect(body.artifact_id).toBe(77);
  });

  it("removes artifacts for a version", async () => {
    const removeArtifact = vi.fn().mockResolvedValue(undefined);
    const deps = baseDeps();
    deps.listConfiguredPackages = vi.fn().mockReturnValue(["uv"]);
    deps.listArtifactsByPackageVersion = vi.fn().mockResolvedValue([
      {
        id: 1,
        version_id: 1,
        os: "linux",
        arch: "x86-64",
        filename: "uv.tar.gz",
        gcs_path: null,
        file_size: null,
        checksum: null,
        checksum_type: null,
        upstream_url: "https://example.test/uv.tar.gz",
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
      },
      {
        id: 2,
        version_id: 1,
        os: "macos",
        arch: "arm64",
        filename: "uv.tar.gz",
        gcs_path: null,
        file_size: null,
        checksum: null,
        checksum_type: null,
        upstream_url: "https://example.test/uv.tar.gz",
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
      },
    ]);
    deps.removeArtifact = removeArtifact;
    const app = createTestApp(deps);

    const response = await request(app).delete("/admin/v1/artifacts/uv/0.6.2");
    const body = response.body as { removed: number };

    expect(response.status).toBe(200);
    expect(body.removed).toBe(2);
    expect(removeArtifact).toHaveBeenCalledTimes(2);
  });

  it("lists failed artifacts, optionally filtered by package", async () => {
    const deps = baseDeps();
    deps.listFailedArtifacts = vi.fn().mockResolvedValue([
      {
        id: 5,
        version_id: 2,
        package_name: "uv",
        version: "0.10.7",
        os: "linux",
        arch: "x86-64",
        filename: "uv-x86_64-unknown-linux-gnu.tar.gz",
        upstream_url:
          "https://github.com/astral-sh/uv/releases/download/0.10.7/uv-x86_64-unknown-linux-gnu.tar.gz",
        gcs_path: null,
        file_size: null,
        checksum: null,
        checksum_type: null,
        status: "failed",
        error_message: "Checksum mismatch",
        download_started_at: new Date(),
        download_completed_at: new Date(),
        removed_at: null,
        created_at: new Date(),
      },
    ]);
    const app = createTestApp(deps);

    const response = await request(app).get("/admin/v1/artifacts/failed?package=uv");
    const body = response.body as {
      count: number;
      artifacts: Array<{ id: number; redownload: string; error_message: string }>;
    };

    expect(response.status).toBe(200);
    expect(body.count).toBe(1);
    expect(body.artifacts[0].id).toBe(5);
    expect(body.artifacts[0].error_message).toBe("Checksum mismatch");
    expect(body.artifacts[0].redownload).toBe("/admin/v1/redownload/uv/0.10.7/linux/x86-64");
    expect(deps.listFailedArtifacts).toHaveBeenCalledWith({ packageName: "uv", limit: undefined });
  });

  describe("GET /admin/v1/jobs/:id — cooling off display", () => {
    function makeJobDetail(overrides: {
      cooling_off_days?: number;
      cooling_off_threshold: string | null;
      artifactStatus?: string;
      artifactVersionSort?: string;
      artifactCreatedAt?: Date;
    }) {
      const {
        cooling_off_days,
        cooling_off_threshold,
        artifactStatus = "pending",
        artifactVersionSort = "000000.000010.000010~",
        artifactCreatedAt = new Date(Date.now() - 6 * 3600_000), // 6 hours ago
      } = overrides;
      return {
        job: {
          id: 99,
          package_name: "uv",
          trigger_type: "scheduled",
          status: "completed",
          versions_found: 1,
          artifacts_queued: 1,
          artifacts_downloaded: 0,
          artifacts_failed: 0,
          error_message: null,
          started_at: new Date(),
          completed_at: new Date(),
        },
        artifacts: [
          {
            id: 1,
            version: "0.10.10",
            version_sort: artifactVersionSort,
            os: "linux",
            arch: "x86-64",
            filename: "uv.tar.gz",
            status: artifactStatus,
            error_message: null,
            download_started_at: null,
            download_completed_at: null,
            created_at: artifactCreatedAt,
          },
        ],
        elapsed_ms: 500,
        cooling_off_days,
        cooling_off_threshold,
      };
    }

    it("returns cooling_off_until = null when threshold is null (bootstrap)", async () => {
      const deps = baseDeps();
      deps.getJob = vi
        .fn()
        .mockResolvedValue(makeJobDetail({ cooling_off_days: 3, cooling_off_threshold: null }));
      const app = createTestApp(deps);

      const res = await request(app).get("/admin/v1/jobs/99").set("Accept", "application/json");
      const body = res.body as {
        artifacts: Array<{ cooling_off_until: string | null }>;
        artifacts_cooling_off: number;
      };

      expect(res.status).toBe(200);
      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });

    it("returns cooling_off_until = null when artifact version_sort is at the threshold", async () => {
      const threshold = "000000.000010.000010~";
      const deps = baseDeps();
      deps.getJob = vi.fn().mockResolvedValue(
        makeJobDetail({
          cooling_off_days: 3,
          cooling_off_threshold: threshold,
          artifactVersionSort: threshold, // exactly at threshold — not above
        }),
      );
      const app = createTestApp(deps);

      const res = await request(app).get("/admin/v1/jobs/99").set("Accept", "application/json");
      const body = res.body as {
        artifacts: Array<{ cooling_off_until: string | null }>;
        artifacts_cooling_off: number;
      };

      expect(res.status).toBe(200);
      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });

    it("returns cooling_off_until set when artifact is above threshold and within the window", async () => {
      const threshold = "000000.000010.000009~"; // 0.10.9
      const sixHoursAgo = new Date(Date.now() - 6 * 3600_000);
      const deps = baseDeps();
      deps.getJob = vi.fn().mockResolvedValue(
        makeJobDetail({
          cooling_off_days: 3,
          cooling_off_threshold: threshold,
          artifactVersionSort: "000000.000010.000010~", // 0.10.10 — above threshold
          artifactCreatedAt: sixHoursAgo,
        }),
      );
      const app = createTestApp(deps);

      const res = await request(app).get("/admin/v1/jobs/99").set("Accept", "application/json");
      const body = res.body as {
        artifacts: Array<{ cooling_off_until: string | null }>;
        artifacts_cooling_off: number;
      };

      expect(res.status).toBe(200);
      expect(body.artifacts[0].cooling_off_until).not.toBeNull();
      // available_at should be ~3 days from created_at
      const availableAt = new Date(body.artifacts[0].cooling_off_until!);
      const expectedAt = new Date(sixHoursAgo.getTime() + 3 * 86_400_000);
      expect(Math.abs(availableAt.getTime() - expectedAt.getTime())).toBeLessThan(1000);
      expect(body.artifacts_cooling_off).toBe(1);
    });

    it("returns cooling_off_until = null when the cooling off window has elapsed", async () => {
      const threshold = "000000.000010.000009~";
      const fourDaysAgo = new Date(Date.now() - 4 * 86_400_000);
      const deps = baseDeps();
      deps.getJob = vi.fn().mockResolvedValue(
        makeJobDetail({
          cooling_off_days: 3,
          cooling_off_threshold: threshold,
          artifactVersionSort: "000000.000010.000010~",
          artifactCreatedAt: fourDaysAgo, // window has passed
        }),
      );
      const app = createTestApp(deps);

      const res = await request(app).get("/admin/v1/jobs/99").set("Accept", "application/json");
      const body = res.body as {
        artifacts: Array<{ cooling_off_until: string | null }>;
        artifacts_cooling_off: number;
      };

      expect(res.status).toBe(200);
      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });

    it("does not mark non-pending artifacts as cooling off", async () => {
      const threshold = "000000.000010.000009~";
      const sixHoursAgo = new Date(Date.now() - 6 * 3600_000);
      const deps = baseDeps();
      deps.getJob = vi.fn().mockResolvedValue(
        makeJobDetail({
          cooling_off_days: 3,
          cooling_off_threshold: threshold,
          artifactVersionSort: "000000.000010.000010~",
          artifactCreatedAt: sixHoursAgo,
          artifactStatus: "available", // already downloaded
        }),
      );
      const app = createTestApp(deps);

      const res = await request(app).get("/admin/v1/jobs/99").set("Accept", "application/json");
      const body = res.body as {
        artifacts: Array<{ cooling_off_until: string | null }>;
        artifacts_cooling_off: number;
      };

      expect(res.status).toBe(200);
      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });
  });

  it("lists jobs and toggles package state", async () => {
    const deps = baseDeps();
    deps.listConfiguredPackages = vi.fn().mockReturnValue(["uv"]);
    deps.listJobs = vi.fn().mockResolvedValue([
      {
        id: 10,
        package_name: "uv",
        trigger_type: "admin",
        status: "failed",
        versions_found: 1,
        artifacts_queued: 1,
        error_message: "failed",
        started_at: new Date(),
        completed_at: new Date(),
      },
    ]);
    deps.setPackageEnabled = vi.fn().mockResolvedValue(true);
    const app = createTestApp(deps);

    const jobsResponse = await request(app).get("/admin/v1/jobs?package=uv&status=failed&limit=20");
    const jobsBody = jobsResponse.body as { jobs: Array<{ id: number }> };
    expect(jobsResponse.status).toBe(200);
    expect(jobsBody.jobs[0].id).toBe(10);

    const patchResponse = await request(app)
      .patch("/admin/v1/packages/uv")
      .send({ enabled: false });
    const patchBody = patchResponse.body as { enabled: boolean };
    expect(patchResponse.status).toBe(200);
    expect(patchBody.enabled).toBe(false);
  });
});
