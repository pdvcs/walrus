import { afterAll, beforeAll, describe, expect, it } from "vitest";
import express from "express";
import request from "supertest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  getVulnProductMetadata,
  reconcilePackageVuln,
  searchAliases,
} from "../../src/db/queries/package-aliases.js";
import { insertAffects, upsertCveFull } from "../../src/db/queries/cves.js";
import { createVulnsRouter } from "../../src/routes/vulns.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const PKG = "product-meta-test";
const UNTRACKED = "product-meta-untracked";
const CVE = "CVE-2099-12345";

describe("GET /api/v1/vulns/products/:name", () => {
  let pool: Pool;
  let app: express.Express;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, UNTRACKED]]);

    await upsertPackage(pool, {
      name: PKG,
      display_name: "Product Meta",
      vendor: "Walrus",
      description: "metadata test",
      website: "https://example.test",
      config_hash: "meta",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["product meta", "pm"],
      cpes: [{ cpe_vendor: "walrus", cpe_product: "product", is_primary: true }],
      osvEcosystem: "npm",
      osvName: "product-meta",
    });
    await upsertPackage(pool, {
      name: UNTRACKED,
      display_name: "Untracked",
      vendor: "Walrus",
      description: null,
      website: null,
      config_hash: "none",
      enabled: true,
    });
    await upsertCveFull(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      severity: "HIGH",
      description: "test",
      raw: { cve: { id: CVE } },
    });
    for (const source of ["nvd", "osv"] as const) {
      await insertAffects(pool, {
        cve_id: CVE,
        package_name: PKG,
        version_start: null,
        version_start_excl: false,
        version_end: "2.0.0",
        version_end_excl: true,
        exact_version: null,
        fixed_in: "2.0.0",
        source,
        raw_cpe: `${source}:range`,
      });
    }

    app = express();
    app.use(
      "/api/v1/vulns",
      createVulnsRouter({
        resolvePackage: async () => ({
          resolved: false,
          slug: null,
          displayName: null,
          confidence: null,
          method: null,
          candidates: [],
        }),
        listAffectsForPackage: async () => [],
        getDataFreshness: async () => ({
          nvd_last_sync: null,
          kev_last_sync: null,
          osv_last_sync: null,
        }),
        logUnresolved: async () => {},
        searchAliases: (query) => searchAliases(pool, query),
        getProductMetadata: (name) => getVulnProductMetadata(pool, name),
      }),
    );
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, UNTRACKED]]);
    await pool.end();
  });

  it("returns package metadata and a distinct CVE count", async () => {
    const res = await request(app).get(`/api/v1/vulns/products/${PKG}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      name: PKG,
      display_name: "Product Meta",
      vendor: "Walrus",
      tracked: true,
      osv: { ecosystem: "npm", name: "product-meta" },
      cve_count: 1,
    });
    expect(res.body.aliases.map((row: { alias: string }) => row.alias)).toEqual([
      "pm",
      "product meta",
    ]);
    expect(res.body.cpes).toEqual([
      { cpe_vendor: "walrus", cpe_product: "product", is_primary: true },
    ]);
  });

  it("returns explicit untracked metadata", async () => {
    const res = await request(app).get(`/api/v1/vulns/products/${UNTRACKED}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      tracked: false,
      aliases: [],
      cpes: [],
      osv: null,
      cve_count: 0,
    });
  });

  it("returns 404 for an unknown package", async () => {
    const res = await request(app).get("/api/v1/vulns/products/not-real");
    expect(res.status).toBe(404);
  });
});
