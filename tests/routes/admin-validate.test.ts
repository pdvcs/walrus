import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import type { Server } from "http";
import http from "http";
import { createAdminRouter } from "../../src/routes/admin.js";
import type { CpeVerifyResult } from "../../src/vuln/cpe-verify.js";

/**
 * Validate flow coverage for the CPE dictionary probe step (WAL-45). The probe is
 * injected, so no NVD traffic happens here; discovery/spot-check steps may fail on the
 * fake repo — the cpe_dictionary step runs before discovery by design so its feedback
 * survives that.
 */

const TOML_WITH_CPE = `
name = "mytool"
display_name = "My Tool"
vendor = "Acme"

[discovery]
type = "github-releases"
repo = "acme/mytool"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+\\\\.\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "unknown-linux-gnu"
arch_upstream = "x86_64"
extension = "tar.gz"
filename_template = "mytool-{arch}-{os}.{ext}"

[vulnerabilities]
cpes = ["acme:mytool", "wrong:pairs"]
`;

const TOML_WITHOUT_VULN = TOML_WITH_CPE.replace(/\[vulnerabilities\][\s\S]*$/, "");

function buildApp(cpeProbe?: (pairs: string[]) => Promise<CpeVerifyResult>) {
  const stub = () => Promise.resolve([]);
  const app = express();
  app.use(express.json());
  app.use(
    "/admin/v1",
    createAdminRouter({
      listConfiguredPackages: () => [],
      getConfiguredPackageMeta: () => [],
      runSync: undefined as never,
      runSyncAll: async () => [],
      startSyncAsync: async () => 1,
      getArtifactByPackageVersionPlatform: async () => null,
      redownloadArtifact: undefined as never,
      listArtifactsByPackageVersion: stub as never,
      removeArtifact: async () => {},
      listFailedArtifacts: async () => [],
      listPendingArtifacts: async () => [],
      listJobs: async () => [],
      getJob: async () => null,
      setPackageEnabled: async () => true,
      removeVersionGroup: async () => ({ versions: 0, artifacts: 0 }),
      removeAllVersionGroups: async () => ({ versions: 0, artifacts: 0 }),
      isPackageEnabled: async () => true,
      listAllPackages: async () => [],
      listVersionGroupNamesForPackage: async () => [],
      listVersionsInGroup: async () => [],
      listArtifactsForVersionId: async () => [],
      getTomlSource: () => null,
      getPackageVulnBadges: async () => ({ tracked: false, byVersion: {} }),
      ...(cpeProbe ? { cpeProbe } : {}),
    }),
  );
  return app;
}

describe("POST /admin/v1/validate-toml — cpe_dictionary step", () => {
  let server: Server;
  let base: string;

  beforeAll(() => {
    server = http.createServer(
      buildApp(async (pairs) => ({
        results: pairs.map((pair) =>
          pair === "acme:mytool"
            ? { pair, matchString: `cpe:2.3:a:${pair}`, status: "verified" as const, hits: 12 }
            : {
                pair,
                matchString: `cpe:2.3:a:${pair}`,
                status: "unverifiable" as const,
                hits: 0,
                detail:
                  "No CPE dictionary entry found — double-check vendor/product spelling against NVD.",
              },
        ),
        verified: 1,
        unverifiable: pairs.length - 1,
        unchecked: 0,
      })),
    );
    server.listen(0);
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("runs before discovery and reports per-pair verdicts; warnings never fail overall", async () => {
    const res = await request(base).post("/admin/v1/validate-toml").send({ toml: TOML_WITH_CPE });

    expect(res.status).toBe(200);
    const names = res.body.steps.map((s: { name: string }) => s.name);
    expect(names.indexOf("cpe_dictionary")).toBeGreaterThan(-1);
    expect(names.indexOf("cpe_dictionary")).toBeLessThan(names.indexOf("discovery"));

    const step = res.body.steps.find((s: { name: string }) => s.name === "cpe_dictionary");
    expect(step.ok).toBe(true); // advisory — never a failure
    expect(step.cpeResults).toEqual([
      { pair: "acme:mytool", status: "verified", hits: 12 },
      { pair: "wrong:pairs", status: "unverifiable", hits: 0 },
    ]);
    expect(step.warning).toMatch(/wrong:pairs.*double-check/i);
  });

  it("omits the step when there are no CPE pairs", async () => {
    const res = await request(base)
      .post("/admin/v1/validate-toml")
      .send({ toml: TOML_WITHOUT_VULN });
    expect(res.status).toBe(200);
    expect(res.body.steps.map((s: { name: string }) => s.name)).not.toContain("cpe_dictionary");
  });

  it("degrades a throwing probe to unchecked verdicts instead of failing validation", async () => {
    const failing = http.createServer(
      buildApp(async () => {
        throw new Error("NVD unreachable");
      }),
    );
    await new Promise<void>((resolve) => failing.listen(0, resolve));
    const fbase = `http://127.0.0.1:${(failing.address() as { port: number }).port}`;
    try {
      const res = await request(fbase)
        .post("/admin/v1/validate-toml")
        .send({ toml: TOML_WITH_CPE });
      expect(res.status).toBe(200);
      const step = res.body.steps.find((s: { name: string }) => s.name === "cpe_dictionary");
      expect(step.ok).toBe(true);
      expect(step.cpeResults.every((r: { status: string }) => r.status === "unchecked")).toBe(true);
      expect(step.warning).toMatch(/NVD unreachable/);
    } finally {
      await new Promise<void>((resolve) => failing.close(() => resolve()));
    }
  });
});
