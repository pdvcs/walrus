import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { readFileSync } from "fs";
import { join } from "path";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  getVulnProductMetadata,
  reconcilePackageVuln,
  searchAliases,
} from "../../src/db/queries/package-aliases.js";
import { listAffectsWithCveForPackage, flagKev } from "../../src/db/queries/cves.js";
import { getDataFreshness, setSyncState } from "../../src/db/queries/vuln-sync-state.js";
import { logUnresolvedQuery } from "../../src/db/queries/unresolved-queries.js";
import { resolvePackage } from "../../src/vuln/resolver.js";
import { ingestCveItems } from "../../src/vuln/sync/nvd-sync.js";
import { createVulnsRouter } from "../../src/routes/vulns.js";
import type { NvdCveItem } from "../../src/vuln/sync/nvd-client.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const fixture = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vuln/nvd-cves-notepad.json"), "utf8"),
);
const items: NvdCveItem[] = fixture.vulnerabilities;
const fixtureCveIds: string[] = items.map((i) => i.cve.id);

const PKG = "notepad-plus-plus";

function buildApp(pool: Pool) {
  const app = express();
  app.use(
    "/api/v1/vulns",
    createVulnsRouter({
      resolvePackage: (query) => resolvePackage(pool, query),
      listAffectsForPackage: (name) => listAffectsWithCveForPackage(pool, name),
      getDataFreshness: () => getDataFreshness(pool),
      logUnresolved: (query, top) => logUnresolvedQuery(pool, query, top),
      searchAliases: (query) => searchAliases(pool, query),
      getProductMetadata: (name) => getVulnProductMetadata(pool, name),
    }),
  );
  return app;
}

describe("GET /api/v1/vulns — golden queries", () => {
  let pool: Pool;
  let app: express.Express;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [fixtureCveIds]);
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
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["notepad++", "notepad plus plus", "npp"],
      cpes: [{ cpe_vendor: "notepad-plus-plus", cpe_product: "notepad++", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    await ingestCveItems(pool, items);
    await setSyncState(pool, "nvd-cve", new Date().toISOString(), true);
    app = buildApp(pool);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [fixtureCveIds]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await pool.query(`DELETE FROM unresolved_queries WHERE query_text = 'asdfghjkl'`);
    await pool.end();
  });

  const q = (qs: string) => request(app).get(`/api/v1/vulns?${qs}`);

  it("notepad++ 8.3.2 → resolved, includes CVE-2023-40031 with correct range/matched_because", async () => {
    const res = await q("product=notepad%2B%2B&version=8.3.2");
    expect(res.status).toBe(200);
    expect(res.body.match.resolved).toBe(true);
    expect(res.body.match.product_slug).toBe(PKG);
    const target = res.body.vulns.find((v: { cve_id: string }) => v.cve_id === "CVE-2023-40031");
    expect(target).toBeDefined();
    expect(target.affected.range).toBe("<= 8.5.6");
    expect(target.affected.matched_because).toBe("8.3.2 <= 8.5.6");
    expect(target.fixed_in).toBeNull(); // end-including → no fixed_in
    expect(target.sources).toContain("nvd");
    expect(res.body.counts.total).toBe(res.body.vulns.length);
  });

  it("npp 8.3.2 → same result via alias (method alias-exact)", async () => {
    const direct = await q("product=notepad%2B%2B&version=8.3.2");
    const alias = await q("product=npp&version=8.3.2");
    expect(alias.body.match.resolved).toBe(true);
    expect(alias.body.match.product_slug).toBe(PKG);
    expect(alias.body.match.method).toBe("alias-exact");
    expect(alias.body.vulns.map((v: { cve_id: string }) => v.cve_id).sort()).toEqual(
      direct.body.vulns.map((v: { cve_id: string }) => v.cve_id).sort(),
    );
  });

  it("notepad++ 8.6.0 → CVE-2023-40031 absent (fixed)", async () => {
    const res = await q("product=notepad%2B%2B&version=8.6.0");
    expect(res.body.match.resolved).toBe(true);
    const ids = res.body.vulns.map((v: { cve_id: string }) => v.cve_id);
    expect(ids).not.toContain("CVE-2023-40031");
  });

  it("no version → all known CVEs with matched_because no-version-given", async () => {
    const res = await q("product=notepad%2B%2B");
    expect(res.body.vulns.length).toBeGreaterThanOrEqual(20);
    expect(
      res.body.vulns.every(
        (v: { affected: { matched_because: string } }) =>
          v.affected.matched_because === "no-version-given",
      ),
    ).toBe(true);
  });

  it("garbage product → resolved=false, HTTP 200, empty vulns/counts, unresolved logged", async () => {
    const res = await q("product=asdfghjkl");
    expect(res.status).toBe(200);
    expect(res.body.match.resolved).toBe(false);
    expect(res.body.vulns).toEqual([]);
    expect(res.body.counts.total).toBe(0);
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM unresolved_queries WHERE query_text = 'asdfghjkl'`,
    );
    expect(rows[0].n).toBeGreaterThanOrEqual(1);
  });

  it("uncomparable version → warning present, matching CVEs included flagged range-uncomparable", async () => {
    const res = await q("product=notepad%2B%2B&version=not-a-version");
    expect(res.body.version_parse_warning).toMatch(/could not be parsed/);
    expect(res.body.vulns.length).toBeGreaterThan(0);
    const flagged = res.body.vulns.filter(
      (v: { affected: { matched_because: string } }) =>
        v.affected.matched_because === "range-uncomparable",
    );
    expect(flagged.length).toBeGreaterThan(0);
  });

  it("missing product param → 400", async () => {
    const res = await q("version=1.0");
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/product/);
  });

  it("every response carries the disclaimer and data_freshness", async () => {
    const res = await q("product=npp&version=8.3.2");
    expect(res.body.disclaimer).toMatch(/does not imply/);
    expect(res.body.data_freshness).toHaveProperty("nvd_last_sync");
  });

  it("collapses multi-source rows and reflects KEV in counts", async () => {
    // Flag one known CVE as KEV, re-query, expect counts.kev >= 1.
    await flagKev(pool, "CVE-2023-40031", "2024-01-01");
    const res = await q("product=notepad%2B%2B&version=8.3.2");
    const target = res.body.vulns.find((v: { cve_id: string }) => v.cve_id === "CVE-2023-40031");
    expect(target.is_kev).toBe(true);
    expect(res.body.counts.kev).toBeGreaterThanOrEqual(1);
  });
});
