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
    listAvailableVersionsByGroup: vi.fn().mockResolvedValue([]),
    listAffectsForPackage: vi.fn().mockResolvedValue([]),
    listVersions: vi.fn().mockResolvedValue([]),
    listAvailableVersionsInGroup: vi.fn().mockResolvedValue([]),
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

  it("lists version groups with the critical-CVE gate applied", async () => {
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
    const listAvailableVersionsByGroup = vi.fn().mockResolvedValue([
      { version: "21.0.3", version_group: "21", is_lts: true },
      { version: "21.0.2", version_group: "21", is_lts: true },
      { version: "17.0.11", version_group: "17", is_lts: true },
    ]);
    deps.listAvailableVersionsByGroup = listAvailableVersionsByGroup;
    deps.listAffectsForPackage = vi.fn().mockResolvedValue([
      {
        cve_id: "CVE-2026-0001",
        version_start: null,
        version_start_excl: false,
        version_end: null,
        version_end_excl: false,
        exact_version: "21.0.3",
        fixed_in: null,
        source: "nvd",
        severity: "CRITICAL",
        cvss_v3_score: "9.8",
        description: null,
        is_kev: false,
        raw: null,
      },
    ]);
    const app = createTestApp(deps);

    const response = await request(app).get("/api/v1/packages/openjdk/groups?os=linux");
    const body = response.body as {
      package: string;
      groups: Array<{ group: string; is_lts: boolean; latest_available: string | null }>;
    };

    expect(response.status).toBe(200);
    expect(listAvailableVersionsByGroup).toHaveBeenCalledWith("openjdk", {
      os: "linux",
      arch: undefined,
    });
    expect(body.groups).toEqual([
      { group: "21", is_lts: true, latest_available: "21.0.2" },
      { group: "17", is_lts: true, latest_available: "17.0.11" },
    ]);
  });

  it("returns 404 for groups of an unknown package", async () => {
    const app = createTestApp(baseDeps());
    const response = await request(app).get("/api/v1/packages/nope/groups");
    expect(response.status).toBe(404);
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
    deps.listAffectsForPackage = vi.fn().mockResolvedValue([
      {
        cve_id: "CVE-2026-0002",
        version_start: null,
        version_start_excl: false,
        version_end: null,
        version_end_excl: false,
        exact_version: "21.0.5+11",
        fixed_in: null,
        source: "nvd",
        severity: "CRITICAL",
        cvss_v3_score: "9.8",
        description: null,
        is_kev: false,
        raw: null,
      },
    ]);
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
      versions: Array<{
        status: string;
        platforms: Array<{ os: string; arch: string; status: string }>;
      }>;
    };

    expect(response.status).toBe(200);
    expect(listVersions).toHaveBeenCalledWith("openjdk", { lts: true });
    expect(body.version_groups).toEqual(["21", "17"]);
    expect(body.versions[0].status).toBe("blocked");
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
    deps.listAvailableVersionsInGroup = vi.fn().mockResolvedValue([
      {
        id: 3,
        package_name: "uv",
        version: "0.6.3",
        version_group: "0.6",
        is_lts: false,
        discovered_at: new Date(),
        version_sort: "0000.0006.0003",
      },
      {
        id: 2,
        package_name: "uv",
        version: "0.6.2",
        version_group: "0.6",
        is_lts: false,
        discovered_at: new Date(),
        version_sort: "0000.0006.0002",
      },
    ]);
    deps.listAffectsForPackage = vi.fn().mockResolvedValue([
      {
        cve_id: "CVE-CRIT",
        version_start: null,
        version_start_excl: false,
        version_end: null,
        version_end_excl: false,
        exact_version: "0.6.3",
        fixed_in: null,
        source: "nvd",
        severity: "CRITICAL",
        cvss_v3_score: "9.8",
        description: null,
        is_kev: false,
        raw: null,
      },
    ]);
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

  it("returns 404 when every available version in the group is blocked", async () => {
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
    deps.listAvailableVersionsInGroup = vi.fn().mockResolvedValue([
      {
        id: 3,
        package_name: "uv",
        version: "0.6.3",
        version_group: "0.6",
        is_lts: false,
        discovered_at: new Date(),
        version_sort: "0000.0006.0003",
      },
    ]);
    deps.listAffectsForPackage = vi.fn().mockResolvedValue([
      {
        cve_id: "CVE-CRIT",
        version_start: null,
        version_start_excl: false,
        version_end: "1",
        version_end_excl: false,
        exact_version: null,
        fixed_in: null,
        source: "nvd",
        severity: "CRITICAL",
        cvss_v3_score: "9.8",
        description: null,
        is_kev: false,
        raw: null,
      },
    ]);
    const app = createTestApp(deps);

    const response = await request(app).get("/api/v1/packages/uv/versions/0.6/latest");

    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "No safe version found for group 0.6" });
    expect(deps.triggerOnDemandSync).not.toHaveBeenCalled();
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
    deps.listAvailableVersionsInGroup = vi.fn().mockResolvedValue([]);
    deps.getRecentSyncJob = vi.fn().mockResolvedValue(null);
    deps.triggerOnDemandSync = triggerOnDemandSync;
    const app = createTestApp(deps);

    const response = await request(app).get("/api/v1/packages/uv/versions/9/latest");

    expect(response.status).toBe(202);
    expect(response.headers["retry-after"]).toBe("30");
    expect(triggerOnDemandSync).toHaveBeenCalledWith("uv");
  });
});
