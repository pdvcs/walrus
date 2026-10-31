import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  reconcilePackageVuln,
  clearPackageVulnConfig,
  loadCpeExclusions,
  loadCpeLookup,
  VulnConfigInput,
} from "../../src/db/queries/package-aliases.js";
import { upsertCveFull, insertAffects } from "../../src/db/queries/cves.js";
import { ingestCveItems } from "../../src/vuln/sync/nvd-sync.js";
import type { CpeExclusion } from "../../src/vuln/cpe.js";

/**
 * The delivery path for `[vulnerabilities].cpe_exclude`, end to end:
 *
 *   TOML rule -> reconcilePackageVuln -> packages.cpe_exclude
 *     -> (a) stored NVD rows the rule now excludes are deleted
 *     -> (b) loadCpeExclusions -> ingestCveItems never writes them again
 *
 * Shaped after the real defect: NVD files Terraform Enterprise as hashicorp:terraform with
 * target_sw "enterprise", and matching on vendor:product alone put CVE-2021-36230 on the CLI.
 * Each half matters on its own — without (a) an existing false positive survives the fix until
 * NVD next modifies that CVE, which for an old CVE may be never.
 */

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-cpex-pkg";
const SHARER = "test-cpex-sharer";
const CVE_ENT = "CVE-2099-21001";
const CVE_CLI = "CVE-2099-21002";
const PAIR = { cpe_vendor: "test-cpex-vendor", cpe_product: "tool" };
const ENTERPRISE = `cpe:2.3:a:${PAIR.cpe_vendor}:${PAIR.cpe_product}:*:*:*:*:*:enterprise:*:*`;
const CLI = `cpe:2.3:a:${PAIR.cpe_vendor}:${PAIR.cpe_product}:*:*:*:*:*:*:*:*`;
const RULE: CpeExclusion[] = [{ target_sw: "enterprise" }];

describe("cpe_exclude delivery path", () => {
  let pool: Pool;

  const input = (name: string, cpeExclude?: CpeExclusion[]): VulnConfigInput => ({
    packageName: name,
    aliases: [name],
    cpes: [{ ...PAIR, is_primary: true }],
    osvEcosystem: null,
    osvName: null,
    cveVersionExtract: null,
    cpeExclude,
  });

  const nvdItem = (id: string, criteria: string) => ({
    cve: {
      id,
      configurations: [
        {
          nodes: [
            {
              operator: "OR",
              negate: false,
              cpeMatch: [{ vulnerable: true, criteria, versionEndExcluding: "2.0.0" }],
            },
          ],
        },
      ],
    },
  });

  const affectsFor = async (pkg: string) =>
    (
      await pool.query<{ cve_id: string }>(
        `SELECT cve_id FROM cve_affects WHERE package_name = $1 AND source = 'nvd' ORDER BY cve_id`,
        [pkg],
      )
    ).rows.map((r) => r.cve_id);

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, SHARER]]);
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [[CVE_ENT, CVE_CLI]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, SHARER]]);
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [[CVE_ENT, CVE_CLI]]);
    for (const name of [PKG, SHARER]) {
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

  async function seedStoredRow(pkg: string, cveId: string, rawCpe: string) {
    await upsertCveFull(pool, {
      id: cveId,
      published_at: null,
      modified_at: null,
      cvss_v3_score: "9.8",
      cvss_v3_vector: null,
      severity: "CRITICAL",
      description: null,
      raw: { cve: { id: cveId } },
    });
    await insertAffects(pool, {
      cve_id: cveId,
      package_name: pkg,
      version_start: null,
      version_start_excl: false,
      version_end: "2.0.0",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "2.0.0",
      source: "nvd",
      raw_cpe: `${rawCpe}|<2.0.0`,
    });
  }

  it("reconcile writes the rules to the package row; removing or clearing nulls them", async () => {
    const read = async () =>
      (
        await pool.query<{ cpe_exclude: unknown }>(
          `SELECT cpe_exclude FROM packages WHERE name = $1`,
          [PKG],
        )
      ).rows[0].cpe_exclude;

    await reconcilePackageVuln(pool, input(PKG, RULE));
    expect(await read()).toEqual(RULE);
    expect((await loadCpeExclusions(pool)).get(PKG)).toEqual(RULE);

    // A stale rule would keep hiding advisories after the package stopped asking for it.
    await reconcilePackageVuln(pool, input(PKG, []));
    expect(await read()).toBeNull();
    expect((await loadCpeExclusions(pool)).has(PKG)).toBe(false);

    await reconcilePackageVuln(pool, input(PKG, RULE));
    await clearPackageVulnConfig(pool, PKG);
    expect(await read()).toBeNull();
  });

  it("reconcile deletes stored rows the rule now excludes, and keeps the rest", async () => {
    await reconcilePackageVuln(pool, input(PKG));
    await seedStoredRow(PKG, CVE_ENT, ENTERPRISE);
    await seedStoredRow(PKG, CVE_CLI, CLI);
    expect(await affectsFor(PKG)).toEqual([CVE_ENT, CVE_CLI]);

    await reconcilePackageVuln(pool, input(PKG, RULE));
    expect(await affectsFor(PKG)).toEqual([CVE_CLI]);
  });

  it("the purge is per package: a sharer of the pair without the rule keeps its row", async () => {
    await reconcilePackageVuln(pool, input(SHARER));
    await seedStoredRow(SHARER, CVE_ENT, ENTERPRISE);

    await reconcilePackageVuln(pool, input(PKG, RULE));
    expect(await affectsFor(SHARER)).toEqual([CVE_ENT]);
  });

  it("ingestion with DB-loaded exclusions never writes the excluded row", async () => {
    await reconcilePackageVuln(pool, input(PKG, RULE));
    await reconcilePackageVuln(pool, input(SHARER));

    // No lookup/exclusions passed: ingestCveItems must load both itself, as the sync paths do.
    const items = [nvdItem(CVE_ENT, ENTERPRISE), nvdItem(CVE_CLI, CLI)];
    await ingestCveItems(pool, items as unknown as Parameters<typeof ingestCveItems>[1]);

    expect(await affectsFor(PKG)).toEqual([CVE_CLI]);
    expect(await affectsFor(SHARER)).toEqual([CVE_ENT, CVE_CLI]);
    // Sanity: the pair really is shared, so the difference above is the rule and nothing else.
    expect((await loadCpeLookup(pool)).get(`${PAIR.cpe_vendor}:${PAIR.cpe_product}`)).toEqual(
      expect.arrayContaining([PKG, SHARER]),
    );
  });
});
