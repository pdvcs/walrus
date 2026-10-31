import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { getPackage, listWatchedPackages } from "../../src/db/queries/packages.js";
import { reconcileAllPackageVulns } from "../../src/services/vuln-config.js";
import { getMetricsSnapshot } from "../../src/services/metrics-snapshot.js";
import type { PackageConfig } from "../../src/types/package-config.js";
import type { WatchConfig } from "../../src/types/watch-config.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const WATCH = "lc-w-watch";
const MOVER = "lc-w-mover";
const SERVED = "lc-w-served";
const NAMES = [WATCH, MOVER, SERVED];

function watchConfig(name: string): WatchConfig {
  return {
    name,
    display_name: name,
    vendor: "T",
    vulnerabilities: {
      cpes: [`acme:${name}`],
      aliases: [],
    },
  } as unknown as WatchConfig;
}

/** Only identity + [vulnerabilities] matter to reconcile; the rest is never read. */
function servedConfig(name: string): PackageConfig {
  return {
    name,
    display_name: name,
    vendor: "T",
    vulnerabilities: { cpes: [`acme:${name}`], aliases: [] },
  } as unknown as PackageConfig;
}

describe("watch-only package lifecycle (WAL-54)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  // Also runs after the last test: a CPE pair left behind here is picked up by every later
  // file's listDistinctCpePairs (nvd-sync asserts exact pair counts).
  async function cleanup() {
    await pool.query(`DELETE FROM cve_affects WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_cpes WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_aliases WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
  }

  afterAll(async () => {
    await cleanup();
    await pool.end();
  });

  beforeEach(cleanup);

  async function cpeCount(name: string): Promise<number> {
    const r = await pool.query(
      `SELECT count(*)::int AS n FROM package_cpes WHERE package_name = $1`,
      [name],
    );
    return r.rows[0].n;
  }

  // Regression: master's tombstone sweep only knew served names, so every boot tombstoned
  // each watch row, wiped its vuln config, and the revive then re-enabled it.
  it("a watch row survives repeated boot reconciles: disabled, not tombstoned, config kept", async () => {
    for (let boot = 0; boot < 3; boot++) {
      await reconcileAllPackageVulns(pool, [servedConfig(SERVED)], [watchConfig(WATCH)]);
      const row = await getPackage(pool, WATCH);
      expect(row!.watch_only).toBe(true);
      expect(row!.enabled).toBe(false);
      expect(row!.removed_at).toBeNull();
      expect(await cpeCount(WATCH)).toBe(1);
    }
    const served = await getPackage(pool, SERVED);
    expect(served!.watch_only).toBe(false);
    expect(served!.enabled).toBe(true);
  });

  it("tombstones a watch row when its TOML is deleted, and revives it still disabled", async () => {
    await reconcileAllPackageVulns(pool, [], [watchConfig(WATCH)]);
    await reconcileAllPackageVulns(pool, [], []);

    let row = await getPackage(pool, WATCH);
    expect(row!.removed_at).not.toBeNull();
    expect(await cpeCount(WATCH)).toBe(0);

    await reconcileAllPackageVulns(pool, [], [watchConfig(WATCH)]);
    row = await getPackage(pool, WATCH);
    expect(row!.removed_at).toBeNull();
    expect(row!.enabled).toBe(false); // revival must not put it in the serving routes
    expect(row!.watch_only).toBe(true);
    expect(await cpeCount(WATCH)).toBe(1);
  });

  it("watch -> served enables the package once; a later operator disable survives", async () => {
    await reconcileAllPackageVulns(pool, [], [watchConfig(MOVER)]);
    expect((await getPackage(pool, MOVER))!.enabled).toBe(false);

    await reconcileAllPackageVulns(pool, [servedConfig(MOVER)], []);
    let row = await getPackage(pool, MOVER);
    expect(row!.watch_only).toBe(false);
    expect(row!.enabled).toBe(true);

    await pool.query(`UPDATE packages SET enabled = false WHERE name = $1`, [MOVER]);
    await reconcileAllPackageVulns(pool, [servedConfig(MOVER)], []);
    row = await getPackage(pool, MOVER);
    expect(row!.enabled).toBe(false);
  });

  it("served -> watch disables the package", async () => {
    await reconcileAllPackageVulns(pool, [servedConfig(MOVER)], []);
    expect((await getPackage(pool, MOVER))!.enabled).toBe(true);

    await reconcileAllPackageVulns(pool, [], [watchConfig(MOVER)]);
    const row = await getPackage(pool, MOVER);
    expect(row!.watch_only).toBe(true);
    expect(row!.enabled).toBe(false);
  });

  it("a name in both directories stays a served package", async () => {
    await reconcileAllPackageVulns(pool, [servedConfig(MOVER)], [watchConfig(MOVER)]);
    const row = await getPackage(pool, MOVER);
    expect(row!.watch_only).toBe(false);
    expect(row!.enabled).toBe(true);
  });

  it("lists only configured watch rows, with their CPE pairs", async () => {
    await reconcileAllPackageVulns(pool, [servedConfig(SERVED)], [watchConfig(WATCH)]);
    const mine = (await listWatchedPackages(pool)).filter((w) => NAMES.includes(w.name));
    expect(mine.map((w) => w.name)).toEqual([WATCH]);
    expect(mine[0].cpes).toEqual([`acme:${WATCH}`]);

    await reconcileAllPackageVulns(pool, [servedConfig(SERVED)], []);
    const after = (await listWatchedPackages(pool)).filter((w) => NAMES.includes(w.name));
    expect(after).toEqual([]); // tombstoned rows drop out of the listing
  });

  it("reports watch rows as their own metrics state, not 'disabled'", async () => {
    const count = async (state: string) => {
      const snap = await getMetricsSnapshot(pool);
      return snap.packages.find((p) => p.state === state)?.count ?? 0;
    };
    const watchBefore = await count("watch");
    const disabledBefore = await count("disabled");

    await reconcileAllPackageVulns(pool, [], [watchConfig(WATCH)]);

    expect(await count("watch")).toBe(watchBefore + 1);
    expect(await count("disabled")).toBe(disabledBefore);
  });
});
