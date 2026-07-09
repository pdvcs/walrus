import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion, listVersions } from "../../src/db/queries/versions.js";
import { reconcilePackageVuln, isPackageTracked } from "../../src/db/queries/package-aliases.js";
import {
  upsertCveFull,
  insertAffects,
  listAffectsWithCveForPackage,
} from "../../src/db/queries/cves.js";
import { getDataFreshness } from "../../src/db/queries/vuln-sync-state.js";
import { getPackage } from "../../src/db/queries/packages.js";
import { generateSortKey } from "../../src/common/version-utils.js";
import { createPackageVulnsRouter } from "../../src/routes/package-vulns.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const TRACKED = "pv-openjdk";
const UNTRACKED = "pv-plain";
const CVE = "CVE-2099-5000";

function buildApp(pool: Pool) {
  const app = express();
  app.use(
    "/api/v1/packages",
    createPackageVulnsRouter({
      packageExists: async (name) => (await getPackage(pool, name)) !== null,
      isTracked: (name) => isPackageTracked(pool, name),
      listCachedVersions: async (name, version) => {
        const rows = await listVersions(pool, name, {});
        const mapped = rows.map((r) => ({ version: r.version, version_group: r.version_group }));
        return version ? mapped.filter((v) => v.version === version) : mapped;
      },
      listAffectsForPackage: (name) => listAffectsWithCveForPackage(pool, name),
      getDataFreshness: () => getDataFreshness(pool),
    }),
  );
  return app;
}

describe("GET /api/v1/packages/:name/vulns", () => {
  let pool: Pool;
  let app: express.Express;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM versions WHERE package_name = ANY($1)`, [[TRACKED, UNTRACKED]]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[TRACKED, UNTRACKED]]);

    for (const name of [TRACKED, UNTRACKED]) {
      await upsertPackage(pool, {
        name,
        display_name: name,
        vendor: "T",
        description: null,
        website: null,
        config_hash: "h",
        enabled: true,
      });
    }
    // Tracked package with two cached versions.
    for (const [version, group] of [
      ["11.0.2", "11"],
      ["21.0.1", "21"],
    ] as const) {
      await insertVersion(pool, {
        package_name: TRACKED,
        version,
        version_group: group,
        is_lts: true,
        version_sort: generateSortKey(version),
      });
    }
    await reconcilePackageVuln(pool, {
      packageName: TRACKED,
      aliases: ["openjdk"],
      cpes: [{ cpe_vendor: "oracle", cpe_product: "openjdk", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    // A CVE affecting < 20 → hits 11.0.2, not 21.0.1.
    await upsertCveFull(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: 9.8,
      cvss_v3_vector: null,
      severity: "CRITICAL",
      description: "boom",
      raw: { cve: { id: CVE } },
    });
    await insertAffects(pool, {
      cve_id: CVE,
      package_name: TRACKED,
      version_start: null,
      version_start_excl: false,
      version_end: "20",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "20",
      source: "nvd",
      raw_cpe: "cpe:2.3:a:oracle:openjdk:*|<20",
    });

    app = buildApp(pool);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM versions WHERE package_name = ANY($1)`, [[TRACKED, UNTRACKED]]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[TRACKED, UNTRACKED]]);
    await pool.end();
  });

  it("lists the CVE on the affected version and zero on the fixed version", async () => {
    const res = await request(app).get(`/api/v1/packages/${TRACKED}/vulns`);
    expect(res.status).toBe(200);
    expect(res.body.tracked).toBe(true);
    const v11 = res.body.versions.find((v: { version: string }) => v.version === "11.0.2");
    const v21 = res.body.versions.find((v: { version: string }) => v.version === "21.0.1");
    expect(v11.counts.total).toBe(1);
    expect(v11.counts.critical).toBe(1);
    expect(v11.vulns[0].cve_id).toBe(CVE);
    expect(v11.vulns[0].fixed_in).toBe("20");
    expect(v21.counts.total).toBe(0);
    expect(res.body).toHaveProperty("data_freshness");
    expect(res.body).toHaveProperty("disclaimer");
  });

  it("?version= restricts to one version", async () => {
    const res = await request(app).get(`/api/v1/packages/${TRACKED}/vulns?version=11.0.2`);
    expect(res.body.versions).toHaveLength(1);
    expect(res.body.versions[0].version).toBe("11.0.2");
  });

  it("unknown version → empty versions array (not 404)", async () => {
    const res = await request(app).get(`/api/v1/packages/${TRACKED}/vulns?version=99.9.9`);
    expect(res.status).toBe(200);
    expect(res.body.versions).toEqual([]);
  });

  it("untracked package → tracked:false with empty versions", async () => {
    const res = await request(app).get(`/api/v1/packages/${UNTRACKED}/vulns`);
    expect(res.status).toBe(200);
    expect(res.body.tracked).toBe(false);
    expect(res.body.versions).toEqual([]);
  });

  it("unknown package → 404", async () => {
    const res = await request(app).get(`/api/v1/packages/does-not-exist/vulns`);
    expect(res.status).toBe(404);
  });
});
