import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import {
  upsertPackage,
  getPackage,
  markRemovedPackagesNotIn,
  reviveTombstonedPackage,
} from "../../src/db/queries/packages.js";
import { reconcileAllPackageVulns } from "../../src/services/vuln-config.js";
import type { PackageConfig } from "../../src/types/package-config.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG_REMOVED = "lc-removed-pkg";
const PKG_KEPT = "lc-kept-pkg";
const PKG_REVIVED = "lc-revived-pkg";
const NAMES = [PKG_REMOVED, PKG_KEPT, PKG_REVIVED];

/** Minimal config shape; only `name` and presence matter to reconcile. */
function configFor(name: string): PackageConfig {
  return {
    name,
    display_name: name,
    vendor: "T",
    discovery: {
      type: "github-releases",
      repo: "acme/x",
    },
    versioning: { type: "semver", version_group_extract: "^v?(\\d+\\.\\d+)", lts_support: false },
    retention: { versions_per_group: 3 },
    platforms: [
      {
        os: "linux",
        arch: "x86-64",
        os_upstream: "unknown-linux-gnu",
        arch_upstream: "x86_64",
        extension: "tar.gz",
        filename_template: "x-{os}-{arch}.{ext}",
        artifact_path_template: null,
      },
    ],
    vulnerabilities: {
      aliases: [],
      cpes: [{ cpe_vendor: "acme", cpe_product: name, is_primary: true }],
      osv: undefined,
    },
  } as unknown as PackageConfig;
}

describe("package removal lifecycle (WAL-53)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    // versions FK has no ON DELETE CASCADE from packages, so children go first.
    await pool.query(`DELETE FROM cve_affects WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM versions WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_cpes WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM cves WHERE id = 'CVE-2099-5500'`);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
  });

  async function seedRow(name: string) {
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

  it("tombstones a DB row whose TOML disappeared: disabled + removed_at set", async () => {
    await seedRow(PKG_REMOVED);
    const removed = await markRemovedPackagesNotIn(pool, [PKG_KEPT]);
    expect(removed).toContain(PKG_REMOVED);
    expect(removed).not.toContain(PKG_KEPT); // untracked-but-configured stays untouched

    const row = await getPackage(pool, PKG_REMOVED);
    expect(row!.enabled).toBe(false);
    expect(row!.removed_at).not.toBeNull();

    // Idempotent: a second pass reports nothing new.
    expect(await markRemovedPackagesNotIn(pool, [PKG_KEPT])).toEqual([]);
  });

  it("revives a tombstoned package when its TOML reappears", async () => {
    await seedRow(PKG_REVIVED);
    await markRemovedPackagesNotIn(pool, []);
    expect((await getPackage(pool, PKG_REVIVED))!.enabled).toBe(false);

    await reviveTombstonedPackage(pool, PKG_REVIVED);
    const row = await getPackage(pool, PKG_REVIVED);
    expect(row!.enabled).toBe(true);
    expect(row!.removed_at).toBeNull();
  });

  it("never resurrects an operator-disabled configured package on reconcile", async () => {
    await seedRow(PKG_KEPT);
    // Operator disables via admin; the TOML is still on disk.
    await pool.query(`UPDATE packages SET enabled = false WHERE name = $1`, [PKG_KEPT]);

    // Reconcile with this package among the configs — must not touch enabled.
    await reconcileAllPackageVulns(pool, [configFor(PKG_KEPT)]);
    const row = await getPackage(pool, PKG_KEPT);
    expect(row!.enabled).toBe(false); // manual disable respected
    expect(row!.removed_at).toBeNull(); // and not mistaken for a removal
  });

  it("reconcile end-to-end: absent TOML loses vuln config but keeps row+versions", async () => {
    await seedRow(PKG_REMOVED);
    // Vuln config as if previously reconciled.
    await pool.query(
      `INSERT INTO package_cpes (package_name, cpe_vendor, cpe_product, is_primary)
       VALUES ($1, 'acme', 'x', true)`,
      [PKG_REMOVED],
    );
    await pool.query(`UPDATE packages SET osv_ecosystem = 'PyPI', osv_name = 'x' WHERE name = $1`, [
      PKG_REMOVED,
    ]);
    await insertVersionAndAffects();

    await reconcileAllPackageVulns(pool, [configFor(PKG_KEPT)]);

    const row = await getPackage(pool, PKG_REMOVED);
    expect(row!.enabled).toBe(false);
    expect(row!.removed_at).not.toBeNull();
    const cpes = await pool.query(
      `SELECT count(*)::int AS n FROM package_cpes WHERE package_name = $1`,
      [PKG_REMOVED],
    );
    expect(cpes.rows[0].n).toBe(0); // cleared
    const affects = await pool.query(
      `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1`,
      [PKG_REMOVED],
    );
    expect(affects.rows[0].n).toBe(0); // derived rows dropped

    const versions = await pool.query(
      `SELECT count(*)::int AS n FROM versions WHERE package_name = $1`,
      [PKG_REMOVED],
    );
    expect(versions.rows[0].n).toBeGreaterThan(0); // history kept — hard delete needs admin action
  });

  async function insertVersionAndAffects() {
    await pool.query(
      `INSERT INTO versions (package_name, version, version_group, is_lts, version_sort)
       VALUES ($1, '1.0.0', '1.0', false, '0001.0000.0000')`,
      [PKG_REMOVED],
    );
    await pool.query(
      `INSERT INTO cves (id, description, raw)
       VALUES ('CVE-2099-5500', 'x', '{}')
       ON CONFLICT (id) DO NOTHING`,
    );
    await pool.query(
      `INSERT INTO cve_affects (cve_id, package_name, source, raw_cpe)
       VALUES ('CVE-2099-5500', $1, 'nvd', 'cpe:2.3:a:acme:x')`,
      [PKG_REMOVED],
    );
  }
});
