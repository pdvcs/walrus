import { describe, it, expect, vi } from "vitest";
import express from "express";
import request from "supertest";
import { createPackageVulnsRouter } from "../../src/routes/package-vulns.js";
import { createWatchlistRouter } from "../../src/routes/watchlist.js";
import { createInternalRouter } from "../../src/routes/internal.js";
import { PostureResponseSchema } from "../../src/routes/schemas.js";
import type { PostureResult } from "../../src/services/posture.js";
import type { WatchedPackageRow } from "../../src/db/queries/packages.js";

const FRESH = {
  nvd_last_sync: null,
  kev_last_sync: null,
  osv_last_sync: null,
  cvss_last_sync: null,
};

function posture(over: Partial<PostureResult> = {}): PostureResult {
  return {
    package: "requests",
    display_name: "Requests",
    version: "2.30.0",
    version_source: "requested",
    latest_version: "2.34.0",
    latest_version_checked_at: "2026-10-31T06:30:00.000Z",
    latest_version_error: null,
    is_latest: false,
    status: "vulnerable",
    unknown_reasons: [],
    coverage: { nvd: "complete", osv: "complete" },
    counts: { total: 1, critical: 0, high: 1, medium: 0, low: 0, unrated: 0, kev: 0 },
    unfixed: 0,
    upgrade_to: "2.31.0",
    vulns: [
      {
        cve_id: "CVE-2023-32681",
        severity: "HIGH",
        severity_source: "v3",
        cvss_v3_score: 7.5,
        cvss_v4_score: null,
        cvss_v2_score: null,
        summary: "Proxy-Authorization leak",
        affected: { range: ">= 2.3.0, < 2.31.0", matched_because: "2.30.0 < 2.31.0" },
        fixed_in: "2.31.0",
        is_kev: false,
        sources: ["nvd"],
        references: [],
        suppression: null,
        confirmed: true,
      },
    ],
    data_freshness: FRESH,
    disclaimer: "d",
    ...over,
  };
}

function packagesApp(getPosture: (n: string, v?: string) => Promise<PostureResult | null>) {
  const app = express();
  app.use(
    "/api/v1/packages",
    createPackageVulnsRouter({
      packageExists: async () => true,
      isTracked: async () => true,
      listCachedVersions: async () => [],
      listAffectsForPackage: async () => [],
      getDataFreshness: async () => FRESH,
      getPosture,
    }),
  );
  return app;
}

describe("GET /api/v1/packages/:name/posture", () => {
  it("returns a schema-valid posture and passes the version through", async () => {
    const get = vi.fn(async () => posture());
    const res = await request(packagesApp(get)).get(
      "/api/v1/packages/requests/posture?version=2.30.0",
    );
    expect(res.status).toBe(200);
    expect(get).toHaveBeenCalledWith("requests", "2.30.0");
    expect(PostureResponseSchema.safeParse(res.body).success).toBe(true);
    expect(res.body.status).toBe("vulnerable");
    expect(res.body.vulns[0]).toMatchObject({ cve_id: "CVE-2023-32681", fixed_in: "2.31.0" });
    expect(res.body.upgrade_to).toBe("2.31.0");
  });

  it("defaults the version to undefined so the service picks the latest", async () => {
    const get = vi.fn(async () => posture({ version_source: "latest" }));
    await request(packagesApp(get)).get("/api/v1/packages/requests/posture");
    expect(get).toHaveBeenCalledWith("requests", undefined);
  });

  it("answers 404 for an unknown package", async () => {
    const res = await request(packagesApp(async () => null)).get(
      "/api/v1/packages/nope/posture?version=1.0.0",
    );
    expect(res.status).toBe(404);
  });

  it("serves an unknown verdict with its reasons rather than an error", async () => {
    const res = await request(
      packagesApp(async () =>
        posture({
          status: "unknown",
          unknown_reasons: ["coverage-incomplete"],
          coverage: { nvd: "complete", osv: "pending" },
          counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, unrated: 0, kev: 0 },
          upgrade_to: null,
          vulns: [],
        }),
      ),
    ).get("/api/v1/packages/requests/posture?version=2.34.0");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("unknown");
    expect(res.body.unknown_reasons).toEqual(["coverage-incomplete"]);
  });
});

function watchedRow(name: string): WatchedPackageRow {
  return {
    name,
    display_name: name,
    vendor: "V",
    osv_ecosystem: null,
    osv_name: null,
    cpes: [],
    vuln_backfill_completed_at: null,
    vuln_backfill_attempts: 0,
    vuln_backfill_last_error: null,
    osv_synced_at: null,
    latest_version: "2.34.0",
    latest_version_checked_at: new Date("2026-10-31T06:30:00Z"),
    latest_version_error: null,
  };
}

describe("GET /api/v1/watchlist", () => {
  function app(getPosture: (n: string) => Promise<PostureResult | null>) {
    const a = express();
    a.use(
      "/api/v1/watchlist",
      createWatchlistRouter({
        listWatched: async () => [watchedRow("requests"), watchedRow("gone")],
        getPosture,
        getDataFreshness: async () => FRESH,
      }),
    );
    return a;
  }

  it("lists each watched package with the posture of its latest version", async () => {
    const res = await request(
      app(async (n) => (n === "requests" ? posture({ version: "2.34.0" }) : null)),
    ).get("/api/v1/watchlist");
    expect(res.status).toBe(200);
    // "gone" had no posture (row vanished between list and lookup): omitted, not an error.
    expect(res.body.packages.map((p: { name: string }) => p.name)).toEqual(["requests"]);
    expect(res.body.packages[0]).toMatchObject({
      latest_version: "2.34.0",
      posture: { version: "2.34.0", status: "vulnerable", upgrade_to: "2.31.0" },
    });
    // The per-advisory list belongs to the per-package endpoint, not the fleet view.
    expect(res.body.packages[0].posture).not.toHaveProperty("vulns");
  });
});

describe("POST /internal/watch-versions/refresh", () => {
  function app(
    refresh?: () => Promise<{
      checked: number;
      updated: number;
      failures: Array<{ package: string; error: string }>;
    }>,
  ) {
    const a = express();
    a.use(
      "/internal",
      createInternalRouter({
        runSync: async () => {
          throw new Error("unused");
        },
        runSyncAll: async () => [],
        vulnSync: {},
        refreshWatchVersions: refresh,
      }),
    );
    return a;
  }

  it("is 200 when every lookup succeeded", async () => {
    const res = await request(app(async () => ({ checked: 2, updated: 2, failures: [] }))).post(
      "/internal/watch-versions/refresh",
    );
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ checked: 2, updated: 2, failures: [] });
  });

  it("is 207 for a partial failure, naming what failed", async () => {
    const res = await request(
      app(async () => ({
        checked: 2,
        updated: 1,
        failures: [{ package: "requests", error: "boom" }],
      })),
    ).post("/internal/watch-versions/refresh");
    expect(res.status).toBe(207);
    expect(res.body.failures[0].package).toBe("requests");
  });

  it("is 502 when every lookup failed, so the scheduler retries and alerts", async () => {
    const res = await request(
      app(async () => ({
        checked: 1,
        updated: 0,
        failures: [{ package: "requests", error: "boom" }],
      })),
    ).post("/internal/watch-versions/refresh");
    expect(res.status).toBe(502);
  });

  it("is 200 when nothing declares [latest] (nothing to fail)", async () => {
    const res = await request(app(async () => ({ checked: 0, updated: 0, failures: [] }))).post(
      "/internal/watch-versions/refresh",
    );
    expect(res.status).toBe(200);
  });

  it("is 503 when refresh is not wired", async () => {
    const res = await request(app()).post("/internal/watch-versions/refresh");
    expect(res.status).toBe(503);
  });
});
