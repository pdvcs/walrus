import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { reconcilePackageVuln } from "../../src/db/queries/package-aliases.js";
import { upsertCveFull, insertAffects } from "../../src/db/queries/cves.js";
import { getVulnHints, BACKFILL_HINT } from "../../src/services/vuln-hints.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const PKG = "hint-pkg";
const CVE = "CVE-2099-8000";

describe("getVulnHints", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
  });

  it("hints to run backfill when a CPE-tracked package has zero NVD affects", async () => {
    // A tracked package (has CPEs) but no NVD affects yet. Every other test file
    // cascade-cleans its own affects on teardown, so global NVD affects are 0 here
    // on the dedicated test DB — no destructive global delete needed.
    await upsertPackage(pool, {
      name: PKG,
      display_name: PKG,
      vendor: "T",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["hint"],
      cpes: [{ cpe_vendor: "v", cpe_product: "p", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });

    const hints = await getVulnHints(pool);
    expect(hints).toContain(BACKFILL_HINT);
  });

  it("does not hint once NVD affects exist", async () => {
    await upsertPackage(pool, {
      name: PKG,
      display_name: PKG,
      vendor: "T",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["hint"],
      cpes: [{ cpe_vendor: "v", cpe_product: "p", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    await upsertCveFull(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      severity: "HIGH",
      description: null,
      raw: { cve: { id: CVE } },
    });
    await insertAffects(pool, {
      cve_id: CVE,
      package_name: PKG,
      version_start: null,
      version_start_excl: false,
      version_end: "2.0",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "2.0",
      source: "nvd",
      raw_cpe: "cpe:2.3:a:v:p:*|<2.0",
    });

    const hints = await getVulnHints(pool);
    expect(hints).not.toContain(BACKFILL_HINT);
  });
});
