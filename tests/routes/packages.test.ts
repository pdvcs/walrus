import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createPackagesRouter, PackagesRouteDeps } from "../../src/routes/packages.js";

function createTestApp(deps: Parameters<typeof createPackagesRouter>[0]): express.Express {
  const app = express();
  app.use("/api/v1/packages", createPackagesRouter(deps));
  return app;
}

function baseDeps(): PackagesRouteDeps {
  return {
    listEnabledPackages: vi.fn().mockResolvedValue([]),
    getPackage: vi.fn().mockResolvedValue(null),
    listVersionGroups: vi.fn().mockResolvedValue([]),
    listVersions: vi.fn().mockResolvedValue([]),
    getLatestVersionInGroup: vi.fn().mockResolvedValue(null),
    listArtifactsForVersion: vi.fn().mockResolvedValue([]),
    getRecentSyncJob: vi.fn().mockResolvedValue(null),
    triggerOnDemandSync: vi.fn().mockResolvedValue(undefined),
  };
}

describe("packages routes", () => {
  it("lists enabled packages", async () => {
    const deps = baseDeps();
    deps.listEnabledPackages = vi.fn().mockResolvedValue([
      {
        name: "uv",
        display_name: "uv",
        vendor: "Astral",
        description: "Fast installer",
        website: "https://example.test",
        config_hash: "x",
        enabled: true,
        created_at: new Date(),
        updated_at: new Date(),
      },
    ]);
    const app = createTestApp(deps);

    const response = await request(app).get("/api/v1/packages");
    const body = response.body as {
      packages: Array<{
        name: string;
        display_name: string;
        vendor: string;
        description: string;
        website: string;
      }>;
    };

    expect(response.status).toBe(200);
    expect(body.packages).toEqual([
      {
        name: "uv",
        display_name: "uv",
        vendor: "Astral",
        description: "Fast installer",
        website: "https://example.test",
      },
    ]);
  });

  it("lists versions with optional lts filter", async () => {
    const listVersions = vi.fn().mockResolvedValue([
      {
        id: 1,
        package_name: "openjdk",
        version: "21.0.5+11",
        version_group: "21",
        is_lts: true,
        discovered_at: new Date(),
        version_sort: "0021.0000.0005",
      },
    ]);

    const deps = baseDeps();
    deps.getPackage = vi.fn().mockResolvedValue({
      name: "openjdk",
      display_name: "OpenJDK",
      vendor: "Temurin",
      description: null,
      website: null,
      config_hash: "x",
      enabled: true,
      created_at: new Date(),
      updated_at: new Date(),
    });
    deps.listVersionGroups = vi.fn().mockResolvedValue(["21", "17"]);
    deps.listVersions = listVersions;
    deps.listArtifactsForVersion = vi.fn().mockResolvedValue([
      {
        id: 10,
        version_id: 1,
        os: "linux",
        arch: "x86-64",
        filename: "openjdk.tar.gz",
        gcs_path: "openjdk/21.0.5/linux/x86-64/openjdk.tar.gz",
        file_size: 123,
        checksum: "abc",
        checksum_type: "sha256",
        upstream_url: "https://example.test/openjdk.tar.gz",
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
      },
    ]);
    const app = createTestApp(deps);

    const response = await request(app).get("/api/v1/packages/openjdk/versions?lts=true");
    const body = response.body as {
      version_groups: string[];
      versions: Array<{ platforms: Array<{ os: string; arch: string; status: string }> }>;
    };

    expect(response.status).toBe(200);
    expect(listVersions).toHaveBeenCalledWith("openjdk", { lts: true });
    expect(body.version_groups).toEqual(["21", "17"]);
    expect(body.versions[0].platforms[0]).toEqual({
      os: "linux",
      arch: "x86-64",
      status: "available",
    });
  });

  it("returns latest artifact for a version group", async () => {
    const deps = baseDeps();
    deps.getPackage = vi.fn().mockResolvedValue({
      name: "uv",
      display_name: "uv",
      vendor: "Astral",
      description: null,
      website: null,
      config_hash: "x",
      enabled: true,
      created_at: new Date(),
      updated_at: new Date(),
    });
    deps.getLatestVersionInGroup = vi.fn().mockResolvedValue({
      id: 2,
      package_name: "uv",
      version: "0.6.2",
      version_group: "0.6",
      is_lts: false,
      discovered_at: new Date(),
      version_sort: "0000.0006.0002",
    });
    deps.listArtifactsForVersion = vi.fn().mockResolvedValue([
      {
        id: 20,
        version_id: 2,
        os: "linux",
        arch: "x86-64",
        filename: "uv.tar.gz",
        gcs_path: "uv/0.6.2/linux/x86-64/uv.tar.gz",
        file_size: 99,
        checksum: "fff",
        checksum_type: "sha256",
        upstream_url: "https://example.test/uv.tar.gz",
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
      },
    ]);
    const app = createTestApp(deps);

    const response = await request(app).get(
      "/api/v1/packages/uv/versions/0.6/latest?os=linux&arch=x86-64",
    );
    const body = response.body as { artifact: { download_url: string } };

    expect(response.status).toBe(200);
    expect(body.artifact.download_url).toBe("/download/uv/0.6.2/linux/x86-64");
  });

  it("triggers on-demand sync and returns 202 when latest is missing", async () => {
    const triggerOnDemandSync = vi.fn().mockResolvedValue(undefined);

    const deps = baseDeps();
    deps.getPackage = vi.fn().mockResolvedValue({
      name: "uv",
      display_name: "uv",
      vendor: "Astral",
      description: null,
      website: null,
      config_hash: "x",
      enabled: true,
      created_at: new Date(),
      updated_at: new Date(),
    });
    deps.getLatestVersionInGroup = vi.fn().mockResolvedValue(null);
    deps.getRecentSyncJob = vi.fn().mockResolvedValue(null);
    deps.triggerOnDemandSync = triggerOnDemandSync;
    const app = createTestApp(deps);

    const response = await request(app).get("/api/v1/packages/uv/versions/9/latest");

    expect(response.status).toBe(202);
    expect(response.headers["retry-after"]).toBe("30");
    expect(triggerOnDemandSync).toHaveBeenCalledWith("uv");
  });
});
