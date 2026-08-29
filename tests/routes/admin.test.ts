import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
  buildRedownloadRequest,
  createAdminRouter,
  AdminRouteDeps,
} from "../../src/routes/admin.js";
import { PackageConfig } from "../../src/types/package-config.js";

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

/** One pending linux artifact for python 3.13.15, as the package detail page sees it. */
function artifact(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 1,
    version_id: 1,
    os: "linux",
    arch: "x86-64",
    filename: "cpython.tar.gz",
    gcs_path: null,
    file_size: null,
    checksum: null,
    checksum_type: null,
    upstream_url: "https://example.test/cpython.tar.gz",
    status: "pending",
    error_message: null,
    download_started_at: null,
    download_completed_at: null,
    removed_at: null,
    created_at: new Date(),
    cooling_off_until: null,
    ...overrides,
  };
}

function depsFor(
  artifacts: ReturnType<typeof artifact>[],
  vulnBadges: { tracked: boolean; byVersion: Record<string, unknown> } = {
    tracked: false,
    byVersion: {},
  },
): AdminRouteDeps {
  const deps = baseDeps();
  deps.listConfiguredPackages = vi.fn().mockReturnValue(["python"]);
  deps.listAllPackages = vi.fn().mockResolvedValue([]);
  deps.listVersionGroupNamesForPackage = vi.fn().mockResolvedValue(["3.13"]);
  deps.listVersionsInGroup = vi
    .fn()
    .mockResolvedValue([{ id: 1, version: "3.13.15", is_lts: false }]);
  deps.listArtifactsForVersionId = vi.fn().mockResolvedValue(artifacts);
  deps.getPackageVulnBadges = vi.fn().mockResolvedValue(vulnBadges);
  return deps;
}

function badges(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    tracked: true,
    byVersion: {
      "3.13.15": { total: 2, critical: 0, high: 2, kev: 0, blocked: false, ...overrides },
    },
  };
}

describe("admin routes", () => {
  it("starts a targeted historical backfill", async () => {
    const deps = baseDeps();
    deps.listConfiguredPackages = vi.fn().mockReturnValue(["python"]);
    deps.isPackageEnabled = vi.fn().mockResolvedValue(true);
    deps.startHistoricalBackfill = vi.fn().mockResolvedValue(42);
    const app = createTestApp(deps);

    const response = await request(app)
      .post("/admin/v1/historical-backfill/python")
      .send({
        version_groups: ["3.11", "3.12"],
        release_page: 2,
        max_releases: 20,
      });

    expect(response.status).toBe(202);
    expect(response.body).toMatchObject({
      package: "python",
      job_id: 42,
      version_groups: ["3.11", "3.12"],
      release_page: 2,
      max_releases: 20,
    });
    expect(deps.startHistoricalBackfill).toHaveBeenCalledWith("python", {
      triggerType: "historical-backfill",
      discovery: {
        releasePage: 2,
        maxReleases: 20,
        versionGroups: ["3.11", "3.12"],
        historical: true,
      },
    });
  });

  it("rejects an unbounded historical backfill request", async () => {
    const deps = baseDeps();
    deps.listConfiguredPackages = vi.fn().mockReturnValue(["python"]);
    const app = createTestApp(deps);

    const response = await request(app).post("/admin/v1/historical-backfill/python").send({
      version_groups: [],
      max_releases: 1000,
    });

    expect(response.status).toBe(400);
  });

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

  describe("redownload request construction (WAL-73 finding 4)", () => {
    // `buildRedownloadRequest` is the piece the earlier test mocks away wholesale, so it runs
    // here for real behind the route.
    function transformedArtifact(overrides: Record<string, unknown> = {}) {
      return {
        id: 91,
        version_id: 1,
        os: "windows",
        arch: "x86-64",
        filename: "Git-2.55.0.5-64-bit.zip",
        gcs_path: "gitwindows/2.55.0.5/windows/x86-64/Git-2.55.0.5-64-bit.zip",
        file_size: 170_000_000,
        checksum: "aa".repeat(32),
        checksum_type: "sha256",
        source_checksum: "bb".repeat(32),
        source_file_size: 70_000_000,
        transform: "tar-bz2-to-zip@1",
        upstream_url: "https://example.test/Git-2.55.0.5-64-bit.tar.bz2",
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
        cooling_off_until: null,
        ...overrides,
      };
    }

    const windowsPlatform = {
      os: "windows",
      arch: "x86-64",
      os_upstream: "windows",
      arch_upstream: "x64",
      extension: "tar.bz2",
      transform: { type: "tar-bz2-to-zip", extension: "zip" },
    };

    function configWith(platforms: unknown[]) {
      return { name: "gitwindows", platforms } as unknown as PackageConfig;
    }

    /** Wires the route's dep to the real builder, the way main.ts does. */
    function appFor(
      art: ReturnType<typeof transformedArtifact>,
      config: PackageConfig | undefined,
    ) {
      const deps = baseDeps();
      deps.listConfiguredPackages = vi.fn().mockReturnValue(["gitwindows"]);
      deps.getArtifactByPackageVersionPlatform = vi
        .fn()
        .mockResolvedValue({ version: "2.55.0.5", artifact: art });
      const downloadArtifact = vi.fn().mockResolvedValue({ status: "available", attempts: 1 });
      deps.redownloadArtifact = async (artifact, packageName, version) =>
        downloadArtifact(
          buildRedownloadRequest(packageName, version, artifact as never, config),
        ) as never;
      return { app: createTestApp(deps), downloadArtifact };
    }

    it("rebuilds a transformed artifact through its transform, against the source digest", async () => {
      const { app, downloadArtifact } = appFor(
        transformedArtifact(),
        configWith([windowsPlatform]),
      );

      const response = await request(app).post(
        "/admin/v1/redownload/gitwindows/2.55.0.5/windows/x86-64",
      );

      expect(response.status).toBe(202);
      expect(downloadArtifact).toHaveBeenCalledWith({
        artifactId: 91,
        upstreamUrl: "https://example.test/Git-2.55.0.5-64-bit.tar.bz2",
        storagePath: "gitwindows/2.55.0.5/windows/x86-64/Git-2.55.0.5-64-bit.zip",
        // the SOURCE digest — the stored checksum describes the zip, not what upstream sends
        expectedChecksum: "bb".repeat(32),
        checksumType: "sha256",
        transform: windowsPlatform.transform,
      });
    });

    it("refuses when the config no longer declares the transform the row was stored by", async () => {
      // Without this the raw tar.bz2 lands under the .zip name and passes every check:
      // expectedChecksum falls back to source_checksum, which is its own digest.
      const { app, downloadArtifact } = appFor(
        transformedArtifact(),
        configWith([{ ...windowsPlatform, transform: undefined }]),
      );

      const response = await request(app).post(
        "/admin/v1/redownload/gitwindows/2.55.0.5/windows/x86-64",
      );
      const body = response.body as { error: string };

      expect(response.status).toBe(409);
      expect(body.error).toMatch(/stored by transform 'tar-bz2-to-zip@1'/);
      expect(body.error).toMatch(/declares no transform/);
      expect(downloadArtifact).not.toHaveBeenCalled();
    });

    it("refuses when the platform itself no longer resolves", async () => {
      const { app, downloadArtifact } = appFor(
        transformedArtifact(),
        configWith([{ ...windowsPlatform, arch: "arm64" }]),
      );

      const response = await request(app).post(
        "/admin/v1/redownload/gitwindows/2.55.0.5/windows/x86-64",
      );

      expect(response.status).toBe(409);
      expect(downloadArtifact).not.toHaveBeenCalled();
    });

    it("still redownloads an untransformed artifact when the config has no transform", async () => {
      const { app, downloadArtifact } = appFor(
        transformedArtifact({
          filename: "uv.tar.gz",
          source_checksum: null,
          source_file_size: null,
          transform: null,
        }),
        configWith([{ ...windowsPlatform, transform: undefined }]),
      );

      const response = await request(app).post(
        "/admin/v1/redownload/gitwindows/2.55.0.5/windows/x86-64",
      );

      expect(response.status).toBe(202);
      expect(downloadArtifact).toHaveBeenCalledWith(
        expect.objectContaining({ transform: undefined, expectedChecksum: "aa".repeat(32) }),
      );
    });
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
    interface TestArtifact {
      version: string;
      version_sort: string;
      status?: string;
      cooling_off_until: Date | null;
    }

    function makeJobDetail(artifacts: TestArtifact[], cooling_off_days = 3) {
      return {
        job: {
          id: 99,
          package_name: "python",
          trigger_type: "scheduled",
          status: "completed",
          versions_found: artifacts.length,
          artifacts_queued: 0,
          artifacts_downloaded: 0,
          artifacts_failed: 0,
          error_message: null,
          started_at: new Date(),
          completed_at: new Date(),
        },
        artifacts: artifacts.map((a, i) => ({
          id: i + 1,
          version: a.version,
          version_sort: a.version_sort,
          os: "linux",
          arch: "x86-64",
          filename: `cpython-${a.version}.tar.gz`,
          status: a.status ?? "pending",
          error_message: null,
          download_started_at: null,
          download_completed_at: null,
          created_at: new Date(Date.now() - 6 * 3600_000),
          cooling_off_until: a.cooling_off_until,
        })),
        elapsed_ms: 500,
        cooling_off_days,
      };
    }

    async function getJobBody(detail: ReturnType<typeof makeJobDetail>) {
      const deps = baseDeps();
      deps.getJob = vi.fn().mockResolvedValue(detail);
      const res = await request(createTestApp(deps))
        .get("/admin/v1/jobs/99")
        .set("Accept", "application/json");
      expect(res.status).toBe(200);
      return res.body as {
        artifacts: Array<{ status: string; cooling_off_until: string | null }>;
        artifacts_cooling_off: number;
      };
    }

    it("reports the cooling_off_until recorded at sync time", async () => {
      const until = new Date(Date.now() + 2.75 * 86_400_000);
      const body = await getJobBody(
        makeJobDetail([
          { version: "3.14.7", version_sort: "000003.000014.000007~", cooling_off_until: until },
        ]),
      );

      expect(new Date(body.artifacts[0].cooling_off_until!).getTime()).toBe(until.getTime());
      expect(body.artifacts_cooling_off).toBe(1);
    });

    it("renders the shared admin navigation on the HTML detail page", async () => {
      const deps = baseDeps();
      deps.getJob = vi.fn().mockResolvedValue(makeJobDetail([]));
      const res = await request(createTestApp(deps))
        .get("/admin/v1/jobs/99")
        .set("Accept", "text/html");

      expect(res.status).toBe(200);
      expect(res.text).toContain('<a href="/admin/v1/jobs" class="active">Jobs</a>');
      expect(res.text).toContain('<a href="/admin/v1/">Packages</a>');
      expect(res.text).toContain('<a href="/admin/v1/validate">Validate TOML</a>');
    });

    it("returns cooling_off_until = null when no embargo was recorded", async () => {
      const body = await getJobBody(
        makeJobDetail([
          { version: "3.14.6", version_sort: "000003.000014.000006~", cooling_off_until: null },
        ]),
      );

      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });

    it("returns cooling_off_until = null once the window has elapsed", async () => {
      const body = await getJobBody(
        makeJobDetail([
          {
            version: "3.14.6",
            version_sort: "000003.000014.000006~",
            cooling_off_until: new Date(Date.now() - 86_400_000),
          },
        ]),
      );

      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });

    it("does not let a stale embargo mask a failed artifact", async () => {
      const body = await getJobBody(
        makeJobDetail([
          {
            version: "3.14.7",
            version_sort: "000003.000014.000007~",
            status: "failed",
            cooling_off_until: new Date(Date.now() + 86_400_000),
          },
        ]),
      );

      expect(body.artifacts[0].cooling_off_until).toBeNull();
      expect(body.artifacts_cooling_off).toBe(0);
    });

    // Regression: a release that lands on several version lines at once (python-build-standalone
    // ships 3.11-3.14 in one dated release) put every line under embargo, but the old display
    // logic compared each artifact against a package-wide max version_sort and only labelled the
    // newest line — the older lines rendered as bare "pending".
    it("marks cooling off artifacts on older version lines, not just the newest", async () => {
      const until = new Date(Date.now() + 2.75 * 86_400_000);
      const body = await getJobBody(
        makeJobDetail([
          { version: "3.14.7", version_sort: "000003.000014.000007~", cooling_off_until: until },
          {
            version: "3.14.6",
            version_sort: "000003.000014.000006~",
            status: "available",
            cooling_off_until: null,
          },
          { version: "3.13.15", version_sort: "000003.000013.000015~", cooling_off_until: until },
          { version: "3.11.15", version_sort: "000003.000011.000015~", cooling_off_until: until },
        ]),
      );

      expect(body.artifacts_cooling_off).toBe(3);
      expect(body.artifacts.map((a) => a.cooling_off_until !== null)).toEqual([
        true,
        false,
        true,
        true,
      ]);
    });
  });

  describe("GET /admin/v1/packages/:name — cooling off display", () => {
    it("shows an embargoed pending artifact as cooling off, with its available-at date", async () => {
      const until = new Date(Date.now() + 2 * 86_400_000);
      const res = await request(createTestApp(depsFor([artifact({ cooling_off_until: until })])))
        .get("/admin/v1/packages/python")
        .set("Accept", "text/html");

      expect(res.status).toBe(200);
      expect(res.text).toContain("cooling-off");
      expect(res.text).toContain(`title="available ${until.toISOString()}"`);
      expect(res.text).not.toContain(">○ pending<");
    });

    it("leaves a pending artifact with no embargo as pending", async () => {
      const res = await request(createTestApp(depsFor([artifact()])))
        .get("/admin/v1/packages/python")
        .set("Accept", "text/html");

      expect(res.status).toBe(200);
      expect(res.text).toContain("○ pending");
      expect(res.text).not.toContain('class="status-cooling-off"');
    });

    it("leaves a pending artifact whose embargo has elapsed as pending", async () => {
      const res = await request(
        createTestApp(
          depsFor([artifact({ cooling_off_until: new Date(Date.now() - 86_400_000) })]),
        ),
      )
        .get("/admin/v1/packages/python")
        .set("Accept", "text/html");

      expect(res.status).toBe(200);
      expect(res.text).toContain("○ pending");
      expect(res.text).not.toContain('class="status-cooling-off"');
    });

    it("does not let a stale embargo mask a failed artifact", async () => {
      const res = await request(
        createTestApp(
          depsFor([
            artifact({ status: "failed", cooling_off_until: new Date(Date.now() + 86_400_000) }),
          ]),
        ),
      )
        .get("/admin/v1/packages/python")
        .set("Accept", "text/html");

      expect(res.status).toBe(200);
      expect(res.text).toContain("✗ failed");
      expect(res.text).not.toContain('class="status-cooling-off"');
    });
  });

  describe("GET /admin/v1/packages/:name — CVE-blocked display", () => {
    async function fetchPage(deps: AdminRouteDeps) {
      const res = await request(createTestApp(deps))
        .get("/admin/v1/packages/python")
        .set("Accept", "text/html");
      expect(res.status).toBe(200);
      return res.text;
    }

    it("badges a blocked version and links it to the CVE list", async () => {
      const html = await fetchPage(
        depsFor([artifact({ status: "available" })], badges({ blocked: true })),
      );

      expect(html).toContain('class="badge badge-blocked"');
      expect(html).toContain("/admin/v1/vulns?product=python&version=3.13.15");
    });

    it("dims an available artifact of a blocked version without hiding its status", async () => {
      const html = await fetchPage(
        depsFor([artifact({ status: "available" })], badges({ blocked: true })),
      );

      expect(html).toContain('class="status-available cell-gated"');
      expect(html).toContain("✓ available");
      expect(html).toContain("blocked: downloads return 403");
    });

    it("does not dim artifacts that were never fetched", async () => {
      const html = await fetchPage(
        depsFor([artifact({ status: "pending" })], badges({ blocked: true })),
      );

      expect(html).toContain("○ pending");
      expect(html).not.toContain('cell-gated"');
    });

    // The count badge and the download gate are different predicates: fail-open range matches
    // count but do not gate, so red CVE styling must not imply blocked on its own.
    it("does not mark a version blocked just because it has critical CVEs", async () => {
      const html = await fetchPage(
        depsFor(
          [artifact({ status: "available" })],
          badges({ total: 3, critical: 2, high: 1, blocked: false }),
        ),
      );

      expect(html).toContain("3 CVE");
      expect(html).not.toContain('class="badge badge-blocked"');
      expect(html).not.toContain('cell-gated"');
    });

    it("renders no vuln badges when the package is not tracked", async () => {
      const html = await fetchPage(depsFor([artifact({ status: "available" })]));

      expect(html).not.toContain('class="badge badge-blocked"');
      expect(html).not.toContain("CVE<");
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

  it("pages the HTML jobs list at 100/page with filter-preserving prev/next links", async () => {
    const deps = baseDeps();
    const seen: Array<{ limit?: number; offset?: number }> = [];
    deps.listJobs = vi.fn().mockImplementation(async (opts) => {
      seen.push(opts);
      // Full page on page 1, 3 rows on page 2 — drives the Next/Previous rendering.
      return (opts.offset ?? 0) === 0 ? fullPage() : shortPage();
    });
    const app = createTestApp(deps);

    const p1 = await request(app)
      .get("/admin/v1/jobs?package=uv&status=failed&page=1")
      .set("Accept", "text/html");
    expect(p1.status).toBe(200);
    // Page 1 → offset 0, fixed limit 100, filters passed through.
    expect(seen[0]).toMatchObject({ limit: 100, offset: 0, packageName: "uv", status: "failed" });
    // A full page offers Next, and its href preserves the filters with page 2.
    expect(p1.text).toMatch(
      /href="\/admin\/v1\/jobs\?page=2&amp;package=uv&amp;status=failed"|href="\/admin\/v1\/jobs\?page=2&package=uv&status=failed"/,
    );

    const p2 = await request(app).get("/admin/v1/jobs?page=2").set("Accept", "text/html");
    expect(seen[1]).toMatchObject({ offset: 100 });
    // A short page hides Next and shows Previous pointing back one page.
    expect(p2.text).not.toMatch(/href="\/admin\/v1\/jobs\?page=3/);
    expect(p2.text).toMatch(/href="\/admin\/v1\/jobs\?page=1"/);
    expect(p2.text).toMatch(/Page 2/);

    function fullPage() {
      return Array.from({ length: 100 }, (_, i) => job(i + 1));
    }
    function shortPage() {
      return [job(201), job(202), job(203)];
    }
    function job(id: number) {
      return {
        id,
        package_name: "uv",
        trigger_type: "admin",
        status: "failed",
        versions_found: 1,
        artifacts_queued: 1,
        error_message: null,
        started_at: new Date(),
        completed_at: new Date(),
      };
    }
  });
});
