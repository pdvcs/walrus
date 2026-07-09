import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion } from "../../src/db/queries/versions.js";
import { reconcilePackageVuln } from "../../src/db/queries/package-aliases.js";
import { upsertCveFull, insertAffects } from "../../src/db/queries/cves.js";
import { insertAdminAction } from "../../src/db/queries/admin-actions.js";
import { generateSortKey } from "../../src/common/version-utils.js";
import { createAdminVulnsRouter } from "../../src/routes/admin-vulns.js";
import { createApp } from "../../src/main.js";
import type { VulnQueryResult } from "../../src/services/vuln-query.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

function resolvedResult(): VulnQueryResult {
  return {
    query: { product: "openjdk", version: "11.0.2" },
    match: {
      resolved: true,
      product_slug: "openjdk",
      display_name: "OpenJDK",
      confidence: 1.0,
      method: "slug-exact",
      candidates: [],
    },
    vulns: [
      {
        cve_id: "CVE-2023-0001",
        severity: "CRITICAL",
        cvss_v3_score: 9.8,
        summary: "boom",
        affected: { range: "< 20", matched_because: "11.0.2 < 20" },
        fixed_in: "20",
        is_kev: true,
        sources: ["nvd"],
        references: [],
      },
    ],
    counts: { total: 1, critical: 1, high: 0, medium: 0, low: 0, kev: 1 },
    data_freshness: { nvd_last_sync: null, kev_last_sync: null, osv_last_sync: null },
    disclaimer: "d",
  };
}

function unresolvedResult(): VulnQueryResult {
  return {
    query: { product: "asdfgh", version: null },
    match: {
      resolved: false,
      product_slug: null,
      display_name: null,
      confidence: null,
      method: null,
      candidates: [{ slug: "openjdk", display_name: "OpenJDK", score: 40 }],
    },
    vulns: [],
    counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, kev: 0 },
    data_freshness: { nvd_last_sync: null, kev_last_sync: null, osv_last_sync: null },
    disclaimer: "d",
  };
}

describe("admin vuln explorer + sync (isolated)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });
  afterAll(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE action_type = 'vuln-sync'`);
    await pool.end();
  });

  function buildApp(overrides: Partial<Parameters<typeof createAdminVulnsRouter>[0]> = {}) {
    const app = express();
    app.use(
      "/admin/v1",
      createAdminVulnsRouter({
        queryVulns: async (product) =>
          product === "asdfgh" ? unresolvedResult() : resolvedResult(),
        getDataFreshness: async () => ({
          nvd_last_sync: null,
          kev_last_sync: null,
          osv_last_sync: null,
        }),
        vulnSyncImpls: { kev: async () => ({ flagged: 3, cleared: 0, skippedUnknown: 0 }) },
        logAdminAction: (details) => insertAdminAction(pool, { action_type: "vuln-sync", details }),
        ...overrides,
      }),
    );
    return app;
  }

  it("renders the explorer page (200 text/html) with freshness panel + sync buttons", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/html/);
    expect(res.text).toMatch(/Vulnerability explorer/);
    expect(res.text).toMatch(/Data freshness/);
    expect(res.text).toMatch(/Sync KEV now/);
  });

  it("renders a CVE table for a resolved query", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns?product=openjdk&version=11.0.2");
    expect(res.text).toContain("CVE-2023-0001");
    expect(res.text).toMatch(/CRITICAL/);
    expect(res.text).toMatch(/KEV/);
  });

  it("renders the not-matched state with suggestions for garbage", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns?product=asdfgh");
    expect(res.text).toMatch(/Not matched/);
    expect(res.text).toMatch(/openjdk/); // candidate suggestion
  });

  it("surfaces operator hints (e.g. run vuln:backfill) as a banner", async () => {
    const app = buildApp({
      getHints: async () => ["No NVD vulnerability data yet — run `npm run vuln:backfill`."],
    });
    const res = await request(app).get("/admin/v1/vulns");
    expect(res.text).toMatch(/No NVD vulnerability data yet/);
    expect(res.text).toContain("<code>npm run vuln:backfill</code>"); // backtick → code
  });

  it("sync trigger runs, records an admin_actions row, returns outcomes", async () => {
    const res = await request(buildApp()).post("/admin/v1/vuln-sync/kev");
    expect(res.status).toBe(200);
    expect(res.body.outcomes[0]).toMatchObject({ source: "kev", ok: true });
    const { rows } = await pool.query(
      `SELECT details FROM admin_actions WHERE action_type = 'vuln-sync' ORDER BY id DESC LIMIT 1`,
    );
    expect(rows[0].details.source).toBe("kev");
  });

  it("unknown sync source → 400", async () => {
    const res = await request(buildApp()).post("/admin/v1/vuln-sync/bogus");
    expect(res.status).toBe(400);
  });
});

describe("per-version CVE badges on package detail page", () => {
  // Uses a real configured package (openjdk) so it appears in the admin router.
  const CVE = "CVE-2099-7000";
  const V_AFFECTED = "11.0.2";
  const V_FIXED = "21.0.1";
  let appPool: Pool;

  beforeAll(async () => {
    appPool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await appPool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await appPool.query(
      `DELETE FROM versions WHERE package_name = 'openjdk' AND version = ANY($1)`,
      [[V_AFFECTED, V_FIXED]],
    );
    await upsertPackage(appPool, {
      name: "openjdk",
      display_name: "Eclipse Temurin OpenJDK",
      vendor: "Eclipse Foundation",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(appPool, {
      packageName: "openjdk",
      aliases: ["openjdk", "temurin"],
      cpes: [{ cpe_vendor: "oracle", cpe_product: "openjdk", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    for (const [version, group] of [
      [V_AFFECTED, "11"],
      [V_FIXED, "21"],
    ] as const) {
      await insertVersion(appPool, {
        package_name: "openjdk",
        version,
        version_group: group,
        is_lts: true,
        version_sort: generateSortKey(version),
      });
    }
    await upsertCveFull(appPool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: 9.8,
      cvss_v3_vector: null,
      severity: "CRITICAL",
      description: "x",
      raw: { cve: { id: CVE } },
    });
    await insertAffects(appPool, {
      cve_id: CVE,
      package_name: "openjdk",
      version_start: null,
      version_start_excl: false,
      version_end: "20",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "20",
      source: "nvd",
      raw_cpe: "cpe:2.3:a:oracle:openjdk:*|<20",
    });
  });

  afterAll(async () => {
    // Fully remove the openjdk package we created so its oracle:openjdk CPE/aliases
    // don't leak into other test files (package delete cascades aliases/cpes/affects).
    await appPool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await appPool.query(`DELETE FROM versions WHERE package_name = 'openjdk'`);
    await appPool.query(`DELETE FROM packages WHERE name = 'openjdk'`);
    await appPool.end();
  });

  it("shows a coloured CVE badge on the affected cached version, none on the fixed one", async () => {
    const app = createApp();
    const res = await request(app).get("/admin/v1/packages/openjdk");
    expect(res.status).toBe(200);
    // Affected version links into the pre-filled explorer with a critical badge.
    expect(res.text).toMatch(/badge-vuln-crit/);
    expect(res.text).toContain(`/admin/v1/vulns?product=openjdk&version=11.0.2`);
    // The fixed version 21.0.1 must not carry a badge link.
    expect(res.text).not.toContain(`version=21.0.1`);
  });
});
