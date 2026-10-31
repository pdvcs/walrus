import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { getPackage } from "../../src/db/queries/packages.js";
import {
  upsertCveFull,
  insertAffects,
  listAffectsWithCveForPackage,
} from "../../src/db/queries/cves.js";
import { getDataFreshness } from "../../src/db/queries/vuln-sync-state.js";
import { getPackageCpes } from "../../src/db/queries/package-aliases.js";
import { resolvePackage } from "../../src/vuln/resolver.js";
import { reconcileAllPackageVulns } from "../../src/services/vuln-config.js";
import { getPosture, type PostureDeps } from "../../src/services/posture.js";
import { refreshWatchLatestVersions } from "../../src/services/latest-version.js";
import type { WatchConfig } from "../../src/types/watch-config.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "wp-watched";
const PKG2 = "wp-watched-nolatest";
const NAMES = [PKG, PKG2];
const CVES = ["CVE-2099-6001", "CVE-2099-6002", "CVE-2099-6003"];

function watch(name: string, withLatest: boolean): WatchConfig {
  return {
    name,
    display_name: name,
    vendor: "V",
    vulnerabilities: { cpes: [`acme:${name}`], aliases: [] },
    ...(withLatest
      ? { latest: { type: "json", url: "https://example.test/x", version_path: "$.v" } }
      : {}),
  } as unknown as WatchConfig;
}

// Real SQL end to end: a watch-only package with no versions of its own, a resolved latest
// version, and advisories — the case the feature exists for.
describe("posture of a watch-only package (WAL-54)", () => {
  let pool: Pool;
  let deps: PostureDeps;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    deps = {
      query: {
        resolvePackage: (q) => resolvePackage(pool, q),
        listAffectsForPackage: (n) => listAffectsWithCveForPackage(pool, n),
        getDataFreshness: () => getDataFreshness(pool),
        logUnresolved: async () => undefined,
      },
      getPackage: (n) => getPackage(pool, n),
      countCpes: async (n) => (await getPackageCpes(pool, n)).length,
      newestCachedVersion: async () => null,
    };
  });

  async function cleanup() {
    await pool.query(`DELETE FROM cve_affects WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [CVES]);
    await pool.query(`DELETE FROM package_cpes WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_aliases WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
  }

  afterAll(async () => {
    await cleanup();
    await pool.end();
  });

  beforeEach(async () => {
    await cleanup();
    await reconcileAllPackageVulns(pool, [], [watch(PKG, true), watch(PKG2, false)]);
  });

  async function advisory(id: string, severity: string | null, end: string, fixed: string | null) {
    await upsertCveFull(pool, {
      id,
      published_at: null,
      modified_at: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      severity,
      description: `desc ${id}`,
      raw: { cve: { id } },
    });
    await insertAffects(pool, {
      cve_id: id,
      package_name: PKG,
      version_start: null,
      version_start_excl: false,
      version_end: end,
      version_end_excl: true,
      exact_version: null,
      fixed_in: fixed,
      source: "nvd",
      raw_cpe: `cpe:2.3:a:acme:${PKG}:*|<${end}`,
    });
  }

  it("is unknown until the NVD backfill and OSV have been read, even with no advisories", async () => {
    await pool.query(`UPDATE packages SET latest_version = '3.0.0' WHERE name = $1`, [PKG]);
    const p = await getPosture(deps, PKG);
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toEqual(["coverage-incomplete"]);
    expect(p!.coverage.nvd).toBe("pending");
  });

  it("becomes clean once covered and nothing affects the latest version", async () => {
    await pool.query(
      `UPDATE packages SET latest_version = '3.0.0', vuln_backfill_completed_at = now() WHERE name = $1`,
      [PKG],
    );
    await advisory(CVES[0], "HIGH", "2.0.0", "2.0.0"); // fixed long before 3.0.0
    const p = await getPosture(deps, PKG);
    expect(p!.status).toBe("clean");
    expect(p!.version).toBe("3.0.0");
    expect(p!.version_source).toBe("latest");
    expect(p!.counts.total).toBe(0);
  });

  it("reports counts by severity, unrated separately, and the fix to move to", async () => {
    await pool.query(
      `UPDATE packages SET latest_version = '3.0.0', vuln_backfill_completed_at = now() WHERE name = $1`,
      [PKG],
    );
    await advisory(CVES[0], "CRITICAL", "3.1.0", "3.1.0");
    await advisory(CVES[1], "MEDIUM", "3.5.0", "3.5.0");
    await advisory(CVES[2], null, "3.2.0", "3.2.0");

    const latest = await getPosture(deps, PKG);
    expect(latest!.status).toBe("vulnerable");
    expect(latest!.counts).toMatchObject({ total: 3, critical: 1, medium: 1, unrated: 1 });
    expect(latest!.upgrade_to).toBe("3.5.0");
    expect(latest!.vulns[0].cve_id).toBe(CVES[0]); // worst first

    // The same package at a version past every fix is clean — version, not package, is judged.
    const newer = await getPosture(deps, PKG, "9.0.0");
    expect(newer!.status).toBe("clean");
    expect(newer!.is_latest).toBe(false);
  });

  it("cannot assess a watch package whose [latest] never resolved, unless told a version", async () => {
    await pool.query(`UPDATE packages SET vuln_backfill_completed_at = now() WHERE name = $1`, [
      PKG2,
    ]);
    const p = await getPosture(deps, PKG2);
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toContain("no-version");

    const explicit = await getPosture(deps, PKG2, "1.0.0");
    expect(explicit!.status).toBe("clean");
  });
});

describe("refreshWatchLatestVersions (WAL-54)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });
  afterAll(async () => {
    await pool.query(`DELETE FROM package_cpes WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_aliases WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
    await pool.end();
  });
  beforeEach(async () => {
    await pool.query(`DELETE FROM package_cpes WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_aliases WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
    await reconcileAllPackageVulns(pool, [], [watch(PKG, true), watch(PKG2, false)]);
  });

  it("stores the resolved version and skips entries with no [latest]", async () => {
    const seen: string[] = [];
    const r = await refreshWatchLatestVersions(
      pool,
      [watch(PKG, true), watch(PKG2, false)],
      async (l) => {
        seen.push(l.type);
        return "4.2.0";
      },
    );
    expect(r).toEqual({ checked: 1, updated: 1, failures: [] });
    const row = await getPackage(pool, PKG);
    expect(row!.latest_version).toBe("4.2.0");
    expect(row!.latest_version_checked_at).not.toBeNull();
    expect(row!.latest_version_error).toBeNull();
    expect((await getPackage(pool, PKG2))!.latest_version_checked_at).toBeNull();
  });

  it("keeps the last good version when a lookup fails, and records why", async () => {
    await refreshWatchLatestVersions(pool, [watch(PKG, true)], async () => "4.2.0");
    const r = await refreshWatchLatestVersions(pool, [watch(PKG, true)], async () => {
      throw new Error("pypi is down");
    });
    expect(r.failures).toEqual([{ package: PKG, error: "pypi is down" }]);
    const row = await getPackage(pool, PKG);
    expect(row!.latest_version).toBe("4.2.0"); // stale beats nothing
    expect(row!.latest_version_error).toBe("pypi is down");

    await refreshWatchLatestVersions(pool, [watch(PKG, true)], async () => "4.3.0");
    const healed = await getPackage(pool, PKG);
    expect(healed!.latest_version).toBe("4.3.0");
    expect(healed!.latest_version_error).toBeNull();
  });

  it("one failing package does not stop the next", async () => {
    let calls = 0;
    const a = watch(PKG, true);
    const b = { ...watch(PKG2, true) } as WatchConfig;
    const r = await refreshWatchLatestVersions(pool, [a, b], async () => {
      if (calls++ === 0) throw new Error("first fails");
      return "1.0.0";
    });
    expect(r).toMatchObject({ checked: 2, updated: 1 });
    expect((await getPackage(pool, PKG2))!.latest_version).toBe("1.0.0");
  });
});
