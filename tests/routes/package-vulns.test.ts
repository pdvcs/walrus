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
import { listAvailabilityHistory } from "../../src/services/availability-history.js";
import type { AvailabilityTransition } from "../../src/services/availability-history.js";

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
      listAvailabilityHistory: (name, version) => listAvailabilityHistory(pool, name, version),
      // Recent-transitions shape shares the same response schema; history covers the parse.
      listRecentTransitions: async () => [] as AvailabilityTransition[],
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

describe("GET /api/v1/packages/:name/availability", () => {
  let pool: Pool;
  let app: express.Express;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM version_availability_events WHERE package_name = $1`, [TRACKED]);
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [TRACKED]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [TRACKED]);

    await upsertPackage(pool, {
      name: TRACKED,
      display_name: TRACKED,
      vendor: "T",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await insertVersion(pool, {
      package_name: TRACKED,
      version: "11.0.2",
      version_group: "11",
      is_lts: true,
      version_sort: generateSortKey("11.0.2"),
    });

    // A v4-caused block (review-02 §3.1's shape): v3 alone looks sub-threshold, and the
    // event must carry every score plus provenance to explain why serving stopped.
    const transition = {
      package_name: TRACKED,
      version: "11.0.2",
      status: "blocked" as const,
      cve_id: CVE,
      cvss_v3_score: "8.1",
      cvss_v4_score: "9.1",
      cvss_v2_score: null,
      severity: "HIGH",
      severity_source: "nvd-cvss-v4",
      source: "nvd",
      trigger_type: "internal",
      created_at: new Date(),
    };
    await pool.query(
      `INSERT INTO version_availability_events
         (package_name, version, status, cve_id, cvss_v3_score, cvss_v4_score,
          cvss_v2_score, severity, severity_source, source, trigger_type, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        transition.package_name,
        transition.version,
        transition.status,
        transition.cve_id,
        transition.cvss_v3_score,
        transition.cvss_v4_score,
        transition.cvss_v2_score,
        transition.severity,
        transition.severity_source,
        transition.source,
        transition.trigger_type,
        transition.created_at,
      ],
    );

    app = buildApp(pool);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM version_availability_events WHERE package_name = $1`, [TRACKED]);
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [TRACKED]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [TRACKED]);
    await pool.end();
  });

  it("returns transitions with score provenance, passing the response schema", async () => {
    const res = await request(app).get(`/api/v1/packages/${TRACKED}/availability?version=11.0.2`);
    expect(res.status).toBe(200);
    expect(res.body.package).toBe(TRACKED);
    const t = res.body.transitions[0];
    expect(t.cve_id).toBe(CVE);
    // NUMERIC arrives as text from pg; the route maps it onto the numeric schema.
    expect(t.cvss_v3_score).toBe(8.1);
    expect(t.cvss_v4_score).toBe(9.1);
    expect(t.cvss_v2_score).toBeNull();
    expect(t.severity).toBe("HIGH");
    expect(t.severity_source).toBe("nvd-cvss-v4");
    expect(t.trigger).toBe("internal");
  });
});
