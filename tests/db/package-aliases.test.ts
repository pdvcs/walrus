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

import { upsertCveFull, insertAffects } from "../../src/db/queries/cves.js";

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
    await pool.query(`DELETE FROM cves WHERE id = 'CVE-2099-26001'`);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.query(`DELETE FROM cves WHERE id = 'CVE-2099-26001'`);
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

  // ── WAL-26: affects rows must not outlive the config that produced them ──

  const CVE = "CVE-2099-26001";

  async function seedAffects(pkg: string, source: "nvd" | "osv", rawCpe: string | null) {
    await upsertCveFull(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      severity: null,
      description: null,
      raw: { cve: { id: CVE } },
    });
    await insertAffects(pool, {
      cve_id: CVE,
      package_name: pkg,
      version_start: null,
      version_start_excl: false,
      version_end: null,
      version_end_excl: true,
      exact_version: null,
      fixed_in: null,
      source,
      raw_cpe: rawCpe,
    });
  }

  async function affectsCount(pkg: string, source: string): Promise<number> {
    const { rows } = await pool.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1 AND source = $2`,
      [pkg, source],
    );
    return rows[0].n;
  }

  it("reconciling away the OSV mapping deletes only that package's osv affects rows", async () => {
    const withOsv = (pkg: string) => ({
      packageName: pkg,
      aliases: [],
      cpes: [{ cpe_vendor: "v1", cpe_product: "p1", is_primary: true }],
      osvEcosystem: "Go",
      osvName: "stdlib",
    });
    await reconcilePackageVuln(pool, withOsv(PKG));
    await reconcilePackageVuln(pool, withOsv(PKG2));
    await seedAffects(PKG, "osv", null);
    await seedAffects(PKG2, "osv", null);
    await seedAffects(PKG, "nvd", "cpe:2.3:a:v1:p1:*:*:*:*:*:*:*:*");

    await reconcilePackageVuln(pool, { ...withOsv(PKG), osvEcosystem: null, osvName: null });

    expect(await affectsCount(PKG, "osv")).toBe(0);
    expect(await affectsCount(PKG, "nvd")).toBe(1); // still-configured pair survives
    expect(await affectsCount(PKG2, "osv")).toBe(1); // other package untouched
  });

  it("reconciling away a CPE pair deletes the nvd rows derived from it, idempotently", async () => {
    const bothPairs = {
      packageName: PKG,
      aliases: [],
      cpes: [
        { cpe_vendor: "v1", cpe_product: "p1", is_primary: true },
        { cpe_vendor: "v2", cpe_product: "p2", is_primary: false },
      ],
      osvEcosystem: "Go",
      osvName: "stdlib",
    };
    await reconcilePackageVuln(pool, bothPairs);
    await seedAffects(PKG, "nvd", "cpe:2.3:a:v1:p1:*:*:*:*:*:*:*:*");
    await seedAffects(PKG, "nvd", "cpe:2.3:a:v2:p2:*:*:*:*:*:*:*:*|<=2.0.0"); // ranged raw_cpe
    await seedAffects(PKG, "osv", null);

    const onePair = { ...bothPairs, cpes: [bothPairs.cpes[0]] };
    await reconcilePackageVuln(pool, onePair);
    await reconcilePackageVuln(pool, onePair); // idempotent rerun

    const { rows } = await pool.query<{ raw_cpe: string }>(
      `SELECT raw_cpe FROM cve_affects WHERE package_name = $1 AND source = 'nvd'`,
      [PKG],
    );
    expect(rows.map((r) => r.raw_cpe)).toEqual(["cpe:2.3:a:v1:p1:*:*:*:*:*:*:*:*"]);
    expect(await affectsCount(PKG, "osv")).toBe(1); // osv mapping kept → rows kept
  });

  it("clearPackageVulnConfig deletes all of the package's affects rows", async () => {
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: [],
      cpes: [{ cpe_vendor: "v1", cpe_product: "p1", is_primary: true }],
      osvEcosystem: "Go",
      osvName: "stdlib",
    });
    await seedAffects(PKG, "nvd", "cpe:2.3:a:v1:p1:*:*:*:*:*:*:*:*");
    await seedAffects(PKG, "osv", null);

    await clearPackageVulnConfig(pool, PKG);

    expect(await affectsCount(PKG, "nvd")).toBe(0);
    expect(await affectsCount(PKG, "osv")).toBe(0);
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
