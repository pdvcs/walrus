import express from "express";
import request from "supertest";
import { Readable } from "stream";
import { describe, expect, it, vi } from "vitest";
import { createAuthenticatedGuard, SESSION_COOKIE } from "../../src/authn/operator.js";
import { createPermissionChecker } from "../../src/authn/permissions.js";
import { mintSession } from "../../src/authn/session.js";
import { createDownloadRouter, type DownloadRouteDeps } from "../../src/routes/download.js";
import { testOperatorAuth } from "../helpers/authn.js";

const VERSION_ROW = {
  id: 1,
  package_name: "uv",
  version: "0.10.10",
  version_group: "0.10",
  version_sort: "000000000000",
  is_lts: false,
  cve_version: null,
};

function artifact(over: Record<string, unknown> = {}) {
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
    ...over,
  };
}

function criticalAffects() {
  return [
    {
      cve_id: "CVE-2026-0001",
      severity: "CRITICAL",
      severity_source: "nvd",
      cvss_v3_score: "9.8",
      cvss_v4_score: null,
      cvss_v2_score: null,
      is_kev: false,
      fixed_in: "0.10.11",
      version_start_including: null,
      version_start_excluding: null,
      version_end_including: null,
      version_end_excluding: null,
      exact_version: "0.10.10",
    },
  ];
}

function setup(artifactRow: ReturnType<typeof artifact>, affects: unknown[] = []) {
  const auth = testOperatorAuth("admin");
  const permissions = createPermissionChecker(auth.runtime.roster);
  const audited = vi.fn();
  const deps: DownloadRouteDeps = {
    getVersion: vi.fn().mockResolvedValue(VERSION_ROW),
    listAffectsForPackage: vi.fn().mockResolvedValue(affects),
    getArtifact: vi.fn().mockResolvedValue(artifactRow),
    streamFromStorage: vi.fn().mockImplementation(() => Readable.from(Buffer.from("bytes"))),
    mayBypassCoolingOff: (req) =>
      req.auth !== undefined && permissions.canDownloadDuringCoolingOff(req.auth.subject),
    onCoolingOffBypass: audited,
  };
  const app = express();
  app.use("/auth", createAuthenticatedGuard(auth.runtime, ""));
  app.use("/auth/download", createDownloadRouter(deps));
  return { app, auth, deps, audited };
}

const URL = "/auth/download/uv/0.10.10/linux/x86-64";
const future = () => new Date(Date.now() + 2 * 86_400_000);

describe("GET /auth/download", () => {
  it("rejects a request with no session", async () => {
    const { app } = setup(artifact());
    const res = await request(app).get(URL);
    expect(res.status).toBe(401);
  });

  it("serves an early-fetched artifact to a roster member and marks it as pre-release", async () => {
    const until = future();
    const { app, auth, audited } = setup(artifact({ cooling_off_until: until }));
    const res = await request(app).get(URL).set("Authorization", `Bearer ${auth.bearer}`);
    expect(res.status).toBe(200);
    expect(res.headers["x-walrus-cooling-off-until"]).toBe(until.toISOString());
    expect(audited).toHaveBeenCalledTimes(1);
  });

  it("gives a signed-in non-roster subject the public 423, not a 403", async () => {
    const { app, auth } = setup(artifact({ cooling_off_until: future() }));
    const token = mintSession("alice", "bearer", auth.runtime.sessions).token;
    const res = await request(app).get(URL).set("Authorization", `Bearer ${token}`);
    expect(res.status).toBe(423);
    expect(res.headers["retry-after"]).toBeDefined();
    expect(res.headers["x-walrus-cooling-off-until"]).toBeUndefined();
  });

  it("still applies the critical-CVE gate to a permitted caller", async () => {
    const { app, auth } = setup(artifact({ cooling_off_until: future() }), criticalAffects());
    const res = await request(app).get(URL).set("Authorization", `Bearer ${auth.bearer}`);
    expect(res.status).toBe(403);
  });

  it("does not set the bypass header when there is no embargo", async () => {
    const { app, auth, audited } = setup(artifact());
    const res = await request(app).get(URL).set("Authorization", `Bearer ${auth.bearer}`);
    expect(res.status).toBe(200);
    expect(res.headers["x-walrus-cooling-off-until"]).toBeUndefined();
    expect(audited).not.toHaveBeenCalled();
  });

  it("returns 404 for an embargoed artifact whose bytes were never fetched", async () => {
    const { app, auth } = setup(
      artifact({ cooling_off_until: future(), status: "pending", gcs_path: null }),
    );
    const res = await request(app).get(URL).set("Authorization", `Bearer ${auth.bearer}`);
    expect(res.status).toBe(404);
  });

  it("accepts the session cookie", async () => {
    const { app, auth } = setup(artifact({ cooling_off_until: future() }));
    const token = mintSession("admin", "cookie", auth.runtime.sessions).token;
    const res = await request(app).get(URL).set("Cookie", `${SESSION_COOKIE}=${token}`);
    expect(res.status).toBe(200);
  });

  it("honours a byte range for a permitted caller", async () => {
    const { app, auth, deps } = setup(artifact({ cooling_off_until: future() }));
    const res = await request(app)
      .get(URL)
      .set("Authorization", `Bearer ${auth.bearer}`)
      .set("Range", "bytes=0-2");
    expect(res.status).toBe(206);
    expect(deps.streamFromStorage).toHaveBeenCalledWith(expect.any(String), { start: 0, end: 2 });
  });
});

describe("public router leaves the embargo alone", () => {
  it("returns 423 for an available artifact whose cooling-off has not ended", async () => {
    const app = express();
    app.use(
      "/download",
      createDownloadRouter({
        getVersion: vi.fn().mockResolvedValue(VERSION_ROW),
        listAffectsForPackage: vi.fn().mockResolvedValue([]),
        getArtifact: vi.fn().mockResolvedValue(artifact({ cooling_off_until: future() })),
        streamFromStorage: vi.fn(),
      }),
    );
    const res = await request(app).get("/download/uv/0.10.10/linux/x86-64");
    expect(res.status).toBe(423);
  });
});
