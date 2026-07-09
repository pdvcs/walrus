import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import TOML from "@iarna/toml";
import { runMigrations } from "../../src/db/client.js";
import { PackageConfigSchema, PackageConfig } from "../../src/types/package-config.js";
import { reconcilePackageVulnFromConfig } from "../../src/services/vuln-config.js";
import {
  getPackageAliases,
  getPackageCpes,
  isPackageTracked,
  listPackagesWithOsv,
} from "../../src/db/queries/package-aliases.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const NAME = "test-vulncfg";

function config(vulnSection: string): PackageConfig {
  const toml = `
name = "${NAME}"
display_name = "Test VulnCfg"
vendor = "Acme"

[discovery]
type = "github-releases"
repo = "acme/x"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "amd64"
extension = "tar.gz"

${vulnSection}
`;
  return PackageConfigSchema.parse(TOML.parse(toml));
}

describe("vuln config boot reconciliation (service)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = $1`, [NAME]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = $1`, [NAME]);
  });

  it("creates the package row and reconciles cpes/aliases/osv from config", async () => {
    await reconcilePackageVulnFromConfig(
      pool,
      config(`[vulnerabilities]
cpes = ["oracle:openjdk"]
osv = { ecosystem = "Bitnami", name = "openjdk" }
aliases = ["openjdk", "jdk"]`),
    );

    const { rows } = await pool.query(`SELECT name FROM packages WHERE name = $1`, [NAME]);
    expect(rows).toHaveLength(1);

    const cpes = await getPackageCpes(pool, NAME);
    expect(cpes.map((c) => `${c.cpe_vendor}:${c.cpe_product}`)).toEqual(["oracle:openjdk"]);

    const aliases = (await getPackageAliases(pool, NAME)).map((a) => a.alias);
    expect(aliases).toContain("openjdk");
    expect(aliases).toContain("jdk");
    expect(aliases).toContain("test vulncfg"); // display_name identity

    expect((await listPackagesWithOsv(pool)).find((o) => o.package_name === NAME)).toBeTruthy();
  });

  it("is idempotent across two boots", async () => {
    const cfg = config(`[vulnerabilities]
cpes = ["oracle:openjdk"]
aliases = ["openjdk"]`);
    await reconcilePackageVulnFromConfig(pool, cfg);
    const first = await getPackageAliases(pool, NAME);
    await reconcilePackageVulnFromConfig(pool, cfg);
    const second = await getPackageAliases(pool, NAME);
    expect(second).toEqual(first);
  });

  it("preserves learned aliases while dropping removed config aliases", async () => {
    await reconcilePackageVulnFromConfig(
      pool,
      config(`[vulnerabilities]\ncpes = ["oracle:openjdk"]\naliases = ["openjdk", "temurin"]`),
    );
    await pool.query(
      `INSERT INTO package_aliases (package_name, alias, source) VALUES ($1, 'learnedalias', 'learned')`,
      [NAME],
    );

    await reconcilePackageVulnFromConfig(
      pool,
      config(`[vulnerabilities]\ncpes = ["oracle:openjdk"]\naliases = ["openjdk"]`),
    );

    const bySource = Object.fromEntries(
      (await getPackageAliases(pool, NAME)).map((a) => [a.alias, a.source]),
    );
    expect(bySource["openjdk"]).toBe("config");
    expect(bySource["temurin"]).toBeUndefined();
    expect(bySource["learnedalias"]).toBe("learned");
  });

  it("packages without the section load fine and get no cpe/alias rows and tracked=false", async () => {
    await reconcilePackageVulnFromConfig(pool, config(""));
    const { rows } = await pool.query(`SELECT name FROM packages WHERE name = $1`, [NAME]);
    expect(rows).toHaveLength(1);
    expect(await getPackageCpes(pool, NAME)).toHaveLength(0);
    expect(await getPackageAliases(pool, NAME)).toHaveLength(0);
    expect(await isPackageTracked(pool, NAME)).toBe(false);
  });

  it("removing the section on a later boot clears prior config metadata", async () => {
    await reconcilePackageVulnFromConfig(
      pool,
      config(`[vulnerabilities]\ncpes = ["oracle:openjdk"]\naliases = ["openjdk"]`),
    );
    expect(await isPackageTracked(pool, NAME)).toBe(true);
    await reconcilePackageVulnFromConfig(pool, config(""));
    expect(await isPackageTracked(pool, NAME)).toBe(false);
  });
});
