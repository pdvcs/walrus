import express from "express";
import request from "supertest";
import { Readable } from "stream";
import { describe, expect, it, vi } from "vitest";
import { createDownloadRouter, DownloadRouteDeps } from "../../src/routes/download.js";

function createTestApp(deps: Parameters<typeof createDownloadRouter>[0]): express.Express {
  const app = express();
  app.use("/download", createDownloadRouter(deps));
  return app;
}

function baseDeps(): DownloadRouteDeps {
  return {
    getVersion: vi.fn().mockResolvedValue(null),
    listAffectsForPackage: vi.fn().mockResolvedValue([]),
    getArtifact: vi.fn().mockResolvedValue(null),
    streamFromStorage: vi.fn().mockReturnValue(Readable.from(Buffer.from(""))),
  };
}

function makeAvailableArtifact(overrides: Partial<{ cooling_off_until: Date | null }> = {}) {
  return {
    id: 10,
    version_id: 1,
    os: "linux",
    arch: "x86-64",
    filename: "uv.tar.gz",
    gcs_path: "uv/0.10.10/linux/x86-64/uv.tar.gz",
    file_size: 5,
    checksum: "abc",
    checksum_type: "sha256",
    upstream_url: "https://example.test/uv.tar.gz",
    status: "available" as const,
    error_message: null,
    download_started_at: null,
    download_completed_at: null,
    removed_at: null,
    sync_job_id: null,
    created_at: new Date(Date.now() - 4 * 86_400_000),
    cooling_off_until: null,
    ...overrides,
  };
}

function makeVersionRow() {
  return {
    id: 1,
    package_name: "uv",
    version: "0.10.10",
    version_group: "0.10",
    is_lts: false,
    discovered_at: new Date(),
    version_sort: "0000.0010.0010",
  };
}

describe("download routes", () => {
  it("streams an available artifact with headers", async () => {
    const deps = baseDeps();
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.getArtifact = vi.fn().mockResolvedValue(makeAvailableArtifact());
    deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(200);
    expect(response.headers["content-type"]).toContain("application/octet-stream");
    expect(response.headers["x-checksum-sha256"]).toBe("abc");
    const body = response.body as Buffer;
    expect(Buffer.isBuffer(body)).toBe(true);
    expect(body.toString("utf8")).toBe("hello");
  });

  it("returns 404 when version is missing", async () => {
    const deps = baseDeps();
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(404);
    const body = response.body as { error: string };
    expect(body.error).toBe("Version not found");
  });

  it("returns 404 when artifact is unavailable", async () => {
    const deps = baseDeps();
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.getArtifact = vi.fn().mockResolvedValue({
      ...makeAvailableArtifact(),
      gcs_path: null,
      status: "failed" as const,
      error_message: "boom",
    });
    const app = createTestApp(deps);

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(404);
    const body = response.body as { error: string };
    expect(body.error).toBe("Artifact not found");
  });

  it("returns 403 without reading storage when the version has a critical CVE", async () => {
    const deps = baseDeps();
    deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
    deps.listAffectsForPackage = vi.fn().mockResolvedValue([
      {
        cve_id: "CVE-CRIT",
        version_start: null,
        version_start_excl: false,
        version_end: null,
        version_end_excl: false,
        exact_version: "0.10.10",
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

    const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

    expect(response.status).toBe(403);
    expect(response.body).toEqual({
      error: "Version blocked due to a critical vulnerability",
    });
    expect(deps.getArtifact).not.toHaveBeenCalled();
    expect(deps.streamFromStorage).not.toHaveBeenCalled();
  });

  describe("cooling off period", () => {
    it("returns 423 with Retry-After when artifact has a future cooling_off_until", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      // cooling_off_until is ~2.75 days from now (3 days - 6 hours elapsed)
      const coolingOffUntil = new Date(Date.now() + (3 * 86_400_000 - 6 * 3600_000));
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(makeAvailableArtifact({ cooling_off_until: coolingOffUntil }));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(423);
      const body = response.body as { error: string; available_at: string };
      expect(body.error).toBe("Artifact is in cooling off period");
      expect(new Date(body.available_at).getTime()).toBeGreaterThan(Date.now());
      const retryAfter = Number(response.headers["retry-after"]);
      expect(retryAfter).toBeGreaterThan(0);
      // Should be roughly 2.75 days away, within 60s tolerance
      expect(retryAfter).toBeCloseTo(3 * 86400 - 6 * 3600, -3);
    });

    it("serves the artifact once cooling_off_until has passed", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      // cooling_off_until is 1 day in the past
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(
          makeAvailableArtifact({ cooling_off_until: new Date(Date.now() - 86_400_000) }),
        );
      deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(200);
    });

    it("serves the artifact when cooling_off_until is null (no cooling off applied)", async () => {
      const deps = baseDeps();
      deps.getVersion = vi.fn().mockResolvedValue(makeVersionRow());
      // cooling_off_until is null — bootstrapped artifact, no cooling off
      deps.getArtifact = vi
        .fn()
        .mockResolvedValue(makeAvailableArtifact({ cooling_off_until: null }));
      deps.streamFromStorage = vi.fn().mockReturnValue(Readable.from(Buffer.from("hello")));
      const app = createTestApp(deps);

      const response = await request(app).get("/download/uv/0.10.10/linux/x86-64");

      expect(response.status).toBe(200);
    });
  });
});
