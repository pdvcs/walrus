import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  upsertCveFull,
  insertAffects,
  getCveById,
  listAffectedPackagesForCve,
} from "../../src/db/queries/cves.js";
import { getDataFreshness } from "../../src/db/queries/vuln-sync-state.js";
import { createCvesRouter } from "../../src/routes/cves.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const PKG = "cvedetail-pkg";
const CVE = "CVE-2023-40031";

describe("GET /api/v1/cves/:cveId", () => {
  let pool: Pool;
  let app: express.Express;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await upsertPackage(pool, {
      name: PKG,
      display_name: "Notepad++",
      vendor: "Don Ho",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await upsertCveFull(pool, {
      id: CVE,
      published_at: "2023-08-01T00:00:00Z",
      modified_at: "2024-01-01T00:00:00Z",
      cvss_v3_score: 7.8,
      cvss_v3_vector: "CVSS:3.1/AV:L",
      severity: "HIGH",
      description: "buffer overflow",
      raw: { cve: { references: [{ url: "https://example.com/adv" }] } },
    });
    await insertAffects(pool, {
      cve_id: CVE,
      package_name: PKG,
      version_start: null,
      version_start_excl: false,
      version_end: "8.5.6",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "8.5.6",
      source: "nvd",
      raw_cpe: "cpe:2.3:a:notepad-plus-plus:notepad++:*|<8.5.6",
    });

    app = express();
    app.use(
      "/api/v1/cves",
      createCvesRouter({
        getCve: (id) => getCveById(pool, id),
        listAffectedPackages: (id) => listAffectedPackagesForCve(pool, id),
        getDataFreshness: () => getDataFreshness(pool),
      }),
    );
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await pool.end();
  });

  it("returns detail with described range + provenance", async () => {
    const res = await request(app).get(`/api/v1/cves/${CVE}`);
    expect(res.status).toBe(200);
    expect(res.body.cve_id).toBe(CVE);
    expect(res.body.severity).toBe("HIGH");
    expect(res.body.cvss_v3_score).toBe(7.8);
    expect(res.body.affected_products).toHaveLength(1);
    expect(res.body.affected_products[0].slug).toBe(PKG);
    expect(res.body.affected_products[0].range).toBe("< 8.5.6");
    expect(res.body.affected_products[0].source).toBe("nvd");
    expect(res.body.references).toContain("https://example.com/adv");
  });

  it("accepts a lowercase id and uppercases it", async () => {
    const res = await request(app).get(`/api/v1/cves/cve-2023-40031`);
    expect(res.status).toBe(200);
    expect(res.body.cve_id).toBe(CVE);
  });

  it("400 for a malformed id", async () => {
    const res = await request(app).get(`/api/v1/cves/CVE-BOGUS`);
    expect(res.status).toBe(400);
  });

  it("404 for an unknown but well-formed id", async () => {
    const res = await request(app).get(`/api/v1/cves/CVE-1999-99999`);
    expect(res.status).toBe(404);
  });
});
