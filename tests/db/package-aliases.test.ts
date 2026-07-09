import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  reconcilePackageVuln,
  clearPackageVulnConfig,
  getPackageAliases,
  getPackageCpes,
  loadCpeLookup,
  listDistinctCpePairs,
  listPackagesWithOsv,
  isPackageTracked,
} from "../../src/db/queries/package-aliases.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-alias-pkg";
const PKG2 = "test-alias-pkg2";

describe("package-aliases queries", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    for (const name of [PKG, PKG2]) {
      await upsertPackage(pool, {
        name,
        display_name: name,
        vendor: "Acme",
        description: null,
        website: null,
        config_hash: "h",
        enabled: true,
      });
    }
  });

  it("reconciles aliases, cpes, and osv mapping from config", async () => {
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["openjdk", "jdk", "java"],
      cpes: [
        { cpe_vendor: "oracle", cpe_product: "openjdk", is_primary: true },
        { cpe_vendor: "eclipse", cpe_product: "temurin", is_primary: false },
      ],
      osvEcosystem: "Bitnami",
      osvName: "openjdk",
    });

    const aliases = await getPackageAliases(pool, PKG);
    expect(aliases.map((a) => a.alias).sort()).toEqual(["java", "jdk", "openjdk"]);
    expect(aliases.every((a) => a.source === "config")).toBe(true);

    const cpes = await getPackageCpes(pool, PKG);
    expect(cpes).toHaveLength(2);
    expect(cpes[0].is_primary).toBe(true); // ordered primary-first
    expect(cpes[0].cpe_vendor).toBe("oracle");

    const osv = await listPackagesWithOsv(pool);
    expect(osv.find((o) => o.package_name === PKG)?.osv_name).toBe("openjdk");

    expect(await isPackageTracked(pool, PKG)).toBe(true);
  });

  it("is idempotent across two identical reconciliations", async () => {
    const input = {
      packageName: PKG,
      aliases: ["a", "b"],
      cpes: [{ cpe_vendor: "v", cpe_product: "p", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    };
    await reconcilePackageVuln(pool, input);
    await reconcilePackageVuln(pool, input);
    expect((await getPackageAliases(pool, PKG)).length).toBe(2);
    expect((await getPackageCpes(pool, PKG)).length).toBe(1);
  });

  it("removes config aliases dropped from config but preserves learned aliases", async () => {
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["keep", "drop"],
      cpes: [],
      osvEcosystem: null,
      osvName: null,
    });
    // Simulate a learned alias captured at runtime.
    await pool.query(
      `INSERT INTO package_aliases (package_name, alias, source) VALUES ($1, 'learnedone', 'learned')`,
      [PKG],
    );

    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["keep"], // 'drop' removed
      cpes: [],
      osvEcosystem: null,
      osvName: null,
    });

    const aliases = await getPackageAliases(pool, PKG);
    const bySource = Object.fromEntries(aliases.map((a) => [a.alias, a.source]));
    expect(bySource["keep"]).toBe("config");
    expect(bySource["drop"]).toBeUndefined();
    expect(bySource["learnedone"]).toBe("learned"); // preserved
  });

  it("removes cpes dropped from config", async () => {
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: [],
      cpes: [
        { cpe_vendor: "v1", cpe_product: "p1", is_primary: true },
        { cpe_vendor: "v2", cpe_product: "p2", is_primary: false },
      ],
      osvEcosystem: null,
      osvName: null,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: [],
      cpes: [{ cpe_vendor: "v1", cpe_product: "p1", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    const cpes = await getPackageCpes(pool, PKG);
    expect(cpes).toHaveLength(1);
    expect(cpes[0].cpe_vendor).toBe("v1");
  });

  it("loadCpeLookup maps a shared pair to multiple packages", async () => {
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: [],
      cpes: [{ cpe_vendor: "oracle", cpe_product: "openjdk", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG2,
      aliases: [],
      cpes: [{ cpe_vendor: "oracle", cpe_product: "openjdk", is_primary: false }],
      osvEcosystem: null,
      osvName: null,
    });
    const lookup = await loadCpeLookup(pool);
    expect(lookup.get("oracle:openjdk")?.sort()).toEqual([PKG, PKG2].sort());

    const pairs = await listDistinctCpePairs(pool);
    expect(pairs.some((p) => p.cpe_vendor === "oracle" && p.cpe_product === "openjdk")).toBe(true);
  });

  it("clearPackageVulnConfig removes config metadata", async () => {
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["x"],
      cpes: [{ cpe_vendor: "v", cpe_product: "p", is_primary: true }],
      osvEcosystem: "E",
      osvName: "n",
    });
    await clearPackageVulnConfig(pool, PKG);
    expect(await getPackageAliases(pool, PKG)).toHaveLength(0);
    expect(await getPackageCpes(pool, PKG)).toHaveLength(0);
    expect(await isPackageTracked(pool, PKG)).toBe(false);
  });
});
