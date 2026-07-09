import { describe, it, expect, beforeAll, afterAll } from "vitest";
import express from "express";
import request from "supertest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { reconcilePackageVuln, searchAliases } from "../../src/db/queries/package-aliases.js";
import { listAffectsWithCveForPackage } from "../../src/db/queries/cves.js";
import { getDataFreshness } from "../../src/db/queries/vuln-sync-state.js";
import { logUnresolvedQuery } from "../../src/db/queries/unresolved-queries.js";
import { resolvePackage } from "../../src/vuln/resolver.js";
import { createVulnsRouter } from "../../src/routes/vulns.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const NAMES = ["srch-openjdk", "srch-nodejs"];

describe("GET /api/v1/vulns/products/search", () => {
  let pool: Pool;
  let app: express.Express;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
    for (const [name, display, aliases] of [
      ["srch-openjdk", "OpenJDK", ["openjdk", "temurin", "jdk", "java"]],
      ["srch-nodejs", "Node.js", ["node", "nodejs", "node.js"]],
    ] as const) {
      await upsertPackage(pool, {
        name,
        display_name: display,
        vendor: "T",
        description: null,
        website: null,
        config_hash: "h",
        enabled: true,
      });
      await reconcilePackageVuln(pool, {
        packageName: name,
        aliases: [...aliases],
        cpes: [{ cpe_vendor: "v", cpe_product: name, is_primary: true }],
        osvEcosystem: null,
        osvName: null,
      });
    }
    app = express();
    app.use(
      "/api/v1/vulns",
      createVulnsRouter({
        resolvePackage: (q) => resolvePackage(pool, q),
        listAffectsForPackage: (n) => listAffectsWithCveForPackage(pool, n),
        getDataFreshness: () => getDataFreshness(pool),
        logUnresolved: (q, top) => logUnresolvedQuery(pool, q, top),
        searchAliases: (q) => searchAliases(pool, q),
      }),
    );
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
    await pool.end();
  });

  it("prefix query ranks the matching package first and returns ≤10", async () => {
    const res = await request(app).get("/api/v1/vulns/products/search?q=openj");
    expect(res.status).toBe(200);
    expect(res.body.results.length).toBeGreaterThanOrEqual(1);
    expect(res.body.results.length).toBeLessThanOrEqual(10);
    expect(res.body.results[0].slug).toBe("srch-openjdk");
    // Unrelated package not returned for a specific prefix.
    expect(res.body.results.some((r: { slug: string }) => r.slug === "srch-nodejs")).toBe(false);
  });

  it("400 when q missing", async () => {
    const res = await request(app).get("/api/v1/vulns/products/search");
    expect(res.status).toBe(400);
  });
});
