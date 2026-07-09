import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import {
  upsertPackage,
  getPackage,
  listPackages,
  setPackageEnabled,
} from "../../src/db/queries/packages.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKGS = ["test-packages-pkg", "test-packages-pkg-a", "test-packages-pkg-b"];

describe("packages queries", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE package_name = ANY($1)`, [PKGS]);
    await pool.query(`DELETE FROM sync_jobs WHERE package_name = ANY($1)`, [PKGS]);
    await pool.query(
      `DELETE FROM artifacts WHERE version_id IN (SELECT id FROM versions WHERE package_name = ANY($1))`,
      [PKGS],
    );
    await pool.query(`DELETE FROM versions WHERE package_name = ANY($1)`, [PKGS]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [PKGS]);
  });

  const basePackage = {
    name: "test-packages-pkg",
    display_name: "Test Package",
    vendor: "Acme",
    description: "A test package",
    website: "https://example.com",
    config_hash: "abc123",
    enabled: true,
  };

  it("inserts and retrieves a package", async () => {
    await upsertPackage(pool, basePackage);
    const pkg = await getPackage(pool, "test-packages-pkg");
    expect(pkg).not.toBeNull();
    expect(pkg!.display_name).toBe("Test Package");
    expect(pkg!.vendor).toBe("Acme");
    expect(pkg!.enabled).toBe(true);
  });

  it("upsert updates an existing package", async () => {
    await upsertPackage(pool, basePackage);
    await upsertPackage(pool, {
      ...basePackage,
      display_name: "Updated Name",
      config_hash: "def456",
    });
    const pkg = await getPackage(pool, "test-packages-pkg");
    expect(pkg!.display_name).toBe("Updated Name");
    expect(pkg!.config_hash).toBe("def456");
  });

  it("returns null for unknown package", async () => {
    const pkg = await getPackage(pool, "nonexistent");
    expect(pkg).toBeNull();
  });

  it("lists only enabled packages when requested", async () => {
    await upsertPackage(pool, { ...basePackage, name: "test-packages-pkg-a", enabled: true });
    await upsertPackage(pool, { ...basePackage, name: "test-packages-pkg-b", enabled: false });
    const all = (await listPackages(pool, false)).filter((p) => PKGS.includes(p.name));
    const enabled = (await listPackages(pool, true)).filter((p) => PKGS.includes(p.name));
    expect(all).toHaveLength(2);
    expect(enabled).toHaveLength(1);
    expect(enabled[0].name).toBe("test-packages-pkg-a");
  });

  it("setPackageEnabled toggles enabled flag", async () => {
    await upsertPackage(pool, basePackage);
    await setPackageEnabled(pool, "test-packages-pkg", false);
    const pkg = await getPackage(pool, "test-packages-pkg");
    expect(pkg!.enabled).toBe(false);
  });
});
