import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  insertVersion,
  getVersion,
  listVersions,
  getLatestVersionInGroup,
  listAvailableVersionsInGroup,
  listVersionGroups,
  listAvailableVersionsByGroup,
  listVersionsOlderThanInGroup,
  getMaxAvailableVersionSort,
  resyncVersionSortKeys,
} from "../../src/db/queries/versions.js";
import { generateSortKey, sortVersionsDesc } from "../../src/common/version-utils.js";
import { insertArtifact, updateArtifactStatus } from "../../src/db/queries/artifacts.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-versions-pkg";

const basePackage = {
  name: PKG,
  display_name: "Test Package",
  vendor: "Acme",
  description: null,
  website: null,
  config_hash: "abc",
  enabled: true,
};

describe("versions queries", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM sync_jobs WHERE package_name = $1`, [PKG]);
    await pool.query(
      `DELETE FROM artifacts WHERE version_id IN (SELECT id FROM versions WHERE package_name = $1)`,
      [PKG],
    );
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await upsertPackage(pool, basePackage);
  });

  it("inserts and retrieves a version", async () => {
    const v = await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });
    expect(v.id).toBeGreaterThan(0);
    expect(v.version).toBe("1.2.3");

    const fetched = await getVersion(pool, PKG, "1.2.3");
    expect(fetched).not.toBeNull();
    expect(fetched!.version_group).toBe("1.2");
  });

  it("insert is idempotent on conflict", async () => {
    const v1 = await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });
    const v2 = await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });
    expect(v1.id).toBe(v2.id);
  });

  it("getVersion returns null for unknown version", async () => {
    const v = await getVersion(pool, PKG, "99.0.0");
    expect(v).toBeNull();
  });

  it("lists versions filtered by group", async () => {
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.4",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0004",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.3.0",
      version_group: "1.3",
      is_lts: true,
      version_sort: "0001.0003.0000",
    });

    const group12 = await listVersions(pool, PKG, { group: "1.2" });
    expect(group12).toHaveLength(2);

    const ltsOnly = await listVersions(pool, PKG, { lts: true });
    expect(ltsOnly).toHaveLength(1);
    expect(ltsOnly[0].version).toBe("1.3.0");
  });

  it("getLatestVersionInGroup returns highest sort key", async () => {
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });
    const v124 = await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.4",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0004",
    });
    const art = await insertArtifact(pool, {
      version_id: v124.id,
      os: "linux",
      arch: "x86-64",
      filename: "pkg.tar.gz",
      upstream_url: "https://example.test/1.2.4/pkg.tar.gz",
    });
    await updateArtifactStatus(pool, art.id, { status: "available" });

    const latest = await getLatestVersionInGroup(pool, PKG, "1.2");
    expect(latest!.version).toBe("1.2.4");
  });

  it("listAvailableVersionsInGroup returns all platform candidates newest first", async () => {
    for (const [version, sort] of [
      ["1.2.3", "0001.0002.0003"],
      ["1.2.4", "0001.0002.0004"],
    ] as const) {
      const row = await insertVersion(pool, {
        package_name: PKG,
        version,
        version_group: "1.2",
        is_lts: false,
        version_sort: sort,
      });
      const artifact = await insertArtifact(pool, {
        version_id: row.id,
        os: "linux",
        arch: "x86-64",
        filename: `${version}.tar.gz`,
        upstream_url: `https://example.test/${version}.tar.gz`,
      });
      await updateArtifactStatus(pool, artifact.id, { status: "available" });
    }

    const versions = await listAvailableVersionsInGroup(pool, PKG, "1.2", {
      os: "linux",
      arch: "x86-64",
    });
    expect(versions.map((row) => row.version)).toEqual(["1.2.4", "1.2.3"]);
  });

  it("listVersionGroups returns distinct groups", async () => {
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.3.0",
      version_group: "1.3",
      is_lts: false,
      version_sort: "0001.0003.0000",
    });

    const groups = await listVersionGroups(pool, PKG);
    expect(groups).toContain("1.2");
    expect(groups).toContain("1.3");
  });

  it("listVersionGroups sorts numerically (0.10 before 0.9)", async () => {
    // Insert versions for groups 0.8, 0.9, 0.10 — lexicographic sort would mis-order these
    await insertVersion(pool, {
      package_name: PKG,
      version: "0.8.0",
      version_group: "0.8",
      is_lts: false,
      version_sort: "0000.0008.0000",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "0.9.0",
      version_group: "0.9",
      is_lts: false,
      version_sort: "0000.0009.0000",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "0.10.0",
      version_group: "0.10",
      is_lts: false,
      version_sort: "0000.0010.0000",
    });

    const groups = await listVersionGroups(pool, PKG);
    expect(groups[0]).toBe("0.10");
    expect(groups[1]).toBe("0.9");
    expect(groups[2]).toBe("0.8");
  });

  it("listVersionsOlderThanInGroup skips the N newest", async () => {
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.1",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0001",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.2",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0002",
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: "1.2.3",
      version_group: "1.2",
      is_lts: false,
      version_sort: "0001.0002.0003",
    });

    const prunable = await listVersionsOlderThanInGroup(pool, PKG, "1.2", 2);
    expect(prunable).toHaveLength(1);
    expect(prunable[0].version).toBe("1.2.1");
  });

  describe("listVersionsOlderThanInGroup and the release embargo", () => {
    async function insertWithEmbargo(version: string, sort: string, coolingOffUntil: Date | null) {
      const v = await insertVersion(pool, {
        package_name: PKG,
        version,
        version_group: "1.2",
        is_lts: false,
        version_sort: sort,
      });
      await insertArtifact(pool, {
        version_id: v.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: `https://example.test/${version}/pkg.tar.gz`,
        cooling_off_until: coolingOffUntil,
      });
      return v;
    }

    const future = () => new Date(Date.now() + 2 * 86_400_000);
    const past = () => new Date(Date.now() - 2 * 86_400_000);

    // The bug this fixes: an embargoed 1.2.4 used to occupy a keep slot, so 1.2.2 was pruned and
    // only 1.2.3 was left downloadable — one servable version despite keepCount = 2.
    it("does not count an embargoed version towards keepCount", async () => {
      await insertWithEmbargo("1.2.4", "0001.0002.0004", future());
      await insertWithEmbargo("1.2.3", "0001.0002.0003", null);
      await insertWithEmbargo("1.2.2", "0001.0002.0002", null);
      await insertWithEmbargo("1.2.1", "0001.0002.0001", null);

      const prunable = await listVersionsOlderThanInGroup(pool, PKG, "1.2", 2);

      expect(prunable.map((v) => v.version)).toEqual(["1.2.1"]);
    });

    it("never returns an embargoed version, even below the keep window", async () => {
      await insertWithEmbargo("1.2.3", "0001.0002.0003", null);
      await insertWithEmbargo("1.2.2", "0001.0002.0002", null);
      await insertWithEmbargo("1.2.1", "0001.0002.0001", future());

      const prunable = await listVersionsOlderThanInGroup(pool, PKG, "1.2", 1);

      expect(prunable.map((v) => v.version)).toEqual(["1.2.2"]);
    });

    it("counts a version whose embargo has elapsed", async () => {
      await insertWithEmbargo("1.2.3", "0001.0002.0003", past());
      await insertWithEmbargo("1.2.2", "0001.0002.0002", past());
      await insertWithEmbargo("1.2.1", "0001.0002.0001", null);

      const prunable = await listVersionsOlderThanInGroup(pool, PKG, "1.2", 2);

      expect(prunable.map((v) => v.version)).toEqual(["1.2.1"]);
    });

    it("prunes embargoed versions too when the exemption is off", async () => {
      await insertWithEmbargo("1.2.2", "0001.0002.0002", future());
      await insertWithEmbargo("1.2.1", "0001.0002.0001", null);

      const prunable = await listVersionsOlderThanInGroup(pool, PKG, "1.2", 0, false);

      expect(prunable.map((v) => v.version)).toEqual(["1.2.2", "1.2.1"]);
    });
  });

  describe("listAvailableVersionsByGroup", () => {
    async function insertWithArtifact(
      version: string,
      group: string,
      sort: string,
      opts: { os?: string; status?: string; is_lts?: boolean } = {},
    ) {
      const v = await insertVersion(pool, {
        package_name: PKG,
        version,
        version_group: group,
        is_lts: opts.is_lts ?? false,
        version_sort: sort,
      });
      const art = await insertArtifact(pool, {
        version_id: v.id,
        os: opts.os ?? "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: `https://example.test/${version}/pkg.tar.gz`,
      });
      if (opts.status !== "pending") {
        await updateArtifactStatus(pool, art.id, { status: opts.status ?? "available" });
      }
    }

    it("returns only versions with available artifacts, newest first", async () => {
      await insertWithArtifact("1.2.3", "1.2", "0001.0002.0003");
      await insertWithArtifact("1.2.4", "1.2", "0001.0002.0004");
      await insertWithArtifact("1.3.0", "1.3", "0001.0003.0000", { status: "pending" });

      const rows = await listAvailableVersionsByGroup(pool, PKG);
      expect(rows.map((r) => r.version)).toEqual(["1.2.4", "1.2.3"]);
      expect(rows[0].version_group).toBe("1.2");
    });

    it("filters by os", async () => {
      await insertWithArtifact("1.2.3", "1.2", "0001.0002.0003", { os: "linux" });
      await insertWithArtifact("1.2.4", "1.2", "0001.0002.0004", { os: "darwin" });

      const rows = await listAvailableVersionsByGroup(pool, PKG, { os: "linux" });
      expect(rows.map((r) => r.version)).toEqual(["1.2.3"]);
    });

    it("orders groups by first appearance = max version_sort", async () => {
      await insertWithArtifact("0.9.0", "0.9", "0000.0009.0000");
      await insertWithArtifact("0.10.0", "0.10", "0000.0010.0000", { is_lts: true });

      const rows = await listAvailableVersionsByGroup(pool, PKG);
      expect(rows[0]).toMatchObject({ version: "0.10.0", version_group: "0.10", is_lts: true });
      expect(rows[1].version_group).toBe("0.9");
    });
  });

  describe("getMaxAvailableVersionSort", () => {
    it("returns null when no versions exist", async () => {
      const result = await getMaxAvailableVersionSort(pool, PKG);
      expect(result).toBeNull();
    });

    it("returns null when versions exist but none have available artifacts", async () => {
      const v = await insertVersion(pool, {
        package_name: PKG,
        version: "1.0.0",
        version_group: "1.0",
        is_lts: false,
        version_sort: "0001.0000.0000",
      });
      await insertArtifact(pool, {
        version_id: v.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/1.0.0/pkg.tar.gz",
      });

      const result = await getMaxAvailableVersionSort(pool, PKG);
      expect(result).toBeNull();
    });

    it("returns the version_sort of the highest version with an available artifact", async () => {
      const v1 = await insertVersion(pool, {
        package_name: PKG,
        version: "1.0.0",
        version_group: "1.0",
        is_lts: false,
        version_sort: "0001.0000.0000",
      });
      const v2 = await insertVersion(pool, {
        package_name: PKG,
        version: "1.1.0",
        version_group: "1.1",
        is_lts: false,
        version_sort: "0001.0001.0000",
      });

      const a1 = await insertArtifact(pool, {
        version_id: v1.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/1.0.0/pkg.tar.gz",
      });
      await insertArtifact(pool, {
        version_id: v2.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/1.1.0/pkg.tar.gz",
      });

      // Only v1's artifact is available; v2's is still pending
      await updateArtifactStatus(pool, a1.id, { status: "available" });

      const result = await getMaxAvailableVersionSort(pool, PKG);
      expect(result).toBe("0001.0000.0000");
    });

    it("returns the max sort among multiple versions with available artifacts", async () => {
      const v1 = await insertVersion(pool, {
        package_name: PKG,
        version: "1.0.0",
        version_group: "1.0",
        is_lts: false,
        version_sort: "0001.0000.0000",
      });
      const v2 = await insertVersion(pool, {
        package_name: PKG,
        version: "1.1.0",
        version_group: "1.1",
        is_lts: false,
        version_sort: "0001.0001.0000",
      });

      const a1 = await insertArtifact(pool, {
        version_id: v1.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/1.0.0/pkg.tar.gz",
      });
      const a2 = await insertArtifact(pool, {
        version_id: v2.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/1.1.0/pkg.tar.gz",
      });

      await updateArtifactStatus(pool, a1.id, { status: "available" });
      await updateArtifactStatus(pool, a2.id, { status: "available" });

      const result = await getMaxAvailableVersionSort(pool, PKG);
      expect(result).toBe("0001.0001.0000");
    });

    it("ignores failed and removed artifacts when computing max", async () => {
      const v1 = await insertVersion(pool, {
        package_name: PKG,
        version: "1.0.0",
        version_group: "1.0",
        is_lts: false,
        version_sort: "0001.0000.0000",
      });
      const v2 = await insertVersion(pool, {
        package_name: PKG,
        version: "2.0.0",
        version_group: "2.0",
        is_lts: false,
        version_sort: "0002.0000.0000",
      });

      const a1 = await insertArtifact(pool, {
        version_id: v1.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/1.0.0/pkg.tar.gz",
      });
      const a2 = await insertArtifact(pool, {
        version_id: v2.id,
        os: "linux",
        arch: "x86-64",
        filename: "pkg.tar.gz",
        upstream_url: "https://example.test/2.0.0/pkg.tar.gz",
      });

      await updateArtifactStatus(pool, a1.id, { status: "available" });
      await updateArtifactStatus(pool, a2.id, { status: "failed", error_message: "network error" });

      // v2 (higher sort) has a failed artifact; only v1 has available
      const result = await getMaxAvailableVersionSort(pool, PKG);
      expect(result).toBe("0001.0000.0000");
    });
  });

  describe("version_sort ordering in SQL (WAL-63)", () => {
    // AC4: the sort key is a stored column, so the ordering has to survive the database's
    // collation — a JS-only comparator would pass the unit tests and still serve the wrong
    // artifact. Mixed component counts and a pre-release in one set.
    const versions = [
      "2025.3.6",
      "2025.3.6.1",
      "2025.2.6.2",
      "2025.2.6.3",
      "2026.2",
      "2026.2.0.1",
      "2026.2.1",
      "2026.2.1-eap",
    ];

    it("orders mixed component counts the same way the sorter does", async () => {
      for (const version of versions) {
        await insertVersion(pool, {
          package_name: PKG,
          version,
          version_group: version.split(".").slice(0, 2).join("."),
          is_lts: false,
          version_sort: generateSortKey(version),
        });
      }

      const { rows } = await pool.query<{ version: string }>(
        "SELECT version FROM versions WHERE package_name = $1 ORDER BY version_sort DESC",
        [PKG],
      );

      expect(rows.map((r) => r.version)).toEqual(sortVersionsDesc(versions));
      expect(rows[0].version).toBe("2026.2.1");
      // The build that WAL-63 was raised for: newer than the version it extends.
      expect(rows.indexOf(rows.find((r) => r.version === "2025.3.6.1")!)).toBeLessThan(
        rows.indexOf(rows.find((r) => r.version === "2025.3.6")!),
      );
    });
  });

  describe("resyncVersionSortKeys", () => {
    it("rewrites keys left behind by an older algorithm, and is idempotent", async () => {
      const stale = await insertVersion(pool, {
        package_name: PKG,
        version: "2025.3.6.1",
        version_group: "2025.3",
        is_lts: false,
        version_sort: "002025.000003.000006.000001", // what the pre-WAL-63 sorter produced
      });
      const current = await insertVersion(pool, {
        package_name: PKG,
        version: "2025.3.6",
        version_group: "2025.3",
        is_lts: false,
        version_sort: generateSortKey("2025.3.6"),
      });

      expect(await resyncVersionSortKeys(pool)).toBeGreaterThanOrEqual(1);

      const repaired = await getVersion(pool, PKG, "2025.3.6.1");
      expect(repaired!.version_sort).toBe(generateSortKey("2025.3.6.1"));
      expect((await getVersion(pool, PKG, "2025.3.6"))!.version_sort).toBe(current.version_sort);
      expect(repaired!.id).toBe(stale.id);

      // Every row now matches the algorithm, so a second pass has nothing to do.
      expect(await resyncVersionSortKeys(pool)).toBe(0);
    });
  });
});
