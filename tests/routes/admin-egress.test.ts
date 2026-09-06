import express from "express";
import request from "supertest";
import { afterEach, describe, expect, it } from "vitest";
import { createAdminRouter, type AdminRouteDeps } from "../../src/routes/admin.js";
import { configureEgress } from "../../src/common/egress-rules.js";

function buildApp(): express.Express {
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
      listArtifactsByPackageVersion: async () => [],
      removeArtifact: async () => {},
      listFailedArtifacts: async () => [],
      listPendingArtifacts: async () => [],
      listJobs: async () => [],
      getJob: async () => null,
      setPackageEnabled: async () => false,
      removeVersionGroup: async () => ({ versions: 0, artifacts: 0 }),
      removeAllVersionGroups: async () => ({ versions: 0, artifacts: 0 }),
      isPackageEnabled: async () => null,
      listAllPackages: async () => [],
      listVersionGroupNamesForPackage: async () => [],
      listVersionsInGroup: async () => [],
      listArtifactsForVersionId: async () => [],
      getTomlSource: () => null,
    } satisfies AdminRouteDeps),
  );
  return app;
}

afterEach(() => {
  configureEgress({ mode: "direct", rules: [] });
});

describe("GET /admin/v1/egress", () => {
  it("reports direct mode with zero rules when nothing is configured (WAL-115 AC4)", async () => {
    configureEgress({ mode: "direct", rules: [] });

    const res = await request(buildApp()).get("/admin/v1/egress");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ mode: "direct", ruleCount: 0 });
  });

  it("reports the configured mode and rule count", async () => {
    configureEgress({
      mode: "strict",
      rules: [
        { match: "https://github.com/", rewrite: "https://artifactory.corp/github-remote/" },
        { match: "https://services.nvd.nist.gov/", rewrite: "https://egress.corp/nvd/" },
      ],
    });

    const res = await request(buildApp()).get("/admin/v1/egress");

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ mode: "strict", ruleCount: 2 });
  });

  it("?url= dry-run reports a match, the rewritten URL, and header NAMES only, never values (WAL-115 AC2)", async () => {
    configureEgress({
      mode: "rules",
      rules: [
        {
          match: "https://github.com/",
          rewrite: "https://artifactory.corp/github-remote/",
          headers: { Authorization: "Bearer super-secret-value" },
        },
      ],
    });

    const res = await request(buildApp())
      .get("/admin/v1/egress")
      .query({ url: "https://github.com/foo/bar/x.tar.gz" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      mode: "rules",
      ruleCount: 1,
      dryRun: {
        url: "https://github.com/foo/bar/x.tar.gz",
        matched: true,
        rewrittenUrl: "https://artifactory.corp/github-remote/foo/bar/x.tar.gz",
        headerNames: ["Authorization"],
      },
    });
    expect(JSON.stringify(res.body)).not.toContain("super-secret-value");
  });

  it("?url= dry-run reports no match without erroring (WAL-115 AC4)", async () => {
    configureEgress({ mode: "rules", rules: [] });

    const res = await request(buildApp())
      .get("/admin/v1/egress")
      .query({ url: "https://example.test/unmatched" });

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      mode: "rules",
      ruleCount: 0,
      dryRun: {
        url: "https://example.test/unmatched",
        matched: false,
        rewrittenUrl: null,
        headerNames: [],
      },
    });
  });

  it("dry-run ignores purpose restriction — reports a match for any traffic class", async () => {
    configureEgress({
      mode: "rules",
      rules: [
        {
          match: "https://services.nvd.nist.gov/",
          purpose: "vuln-feed",
          rewrite: "https://egress.corp/nvd/",
        },
      ],
    });

    const res = await request(buildApp())
      .get("/admin/v1/egress")
      .query({ url: "https://services.nvd.nist.gov/rest/json/cves/2.0" });

    expect(res.body.dryRun.matched).toBe(true);
  });
});
