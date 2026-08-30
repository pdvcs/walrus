import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion, getMaxAvailableVersionSort } from "../../src/db/queries/versions.js";
import { insertArtifact, updateArtifactStatus } from "../../src/db/queries/artifacts.js";
import { computeCoolingOffUntil } from "../../src/common/retention-window.js";
import { generateSortKey } from "../../src/common/version-utils.js";
import { PackageConfig } from "../../src/types/package-config.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-cooling-off-pkg";
const DAY = 86_400_000;
const retention = { versions_per_group: 2, cooling_off_days: 3 } as PackageConfig["retention"];

/**
 * WAL-91. The embargo end is not written once — `insertArtifact` recomputes and rewrites it on
 * every sync for as long as the artifact is still `pending`. These tests run the real sequence a
 * sync performs (watermark → version row → embargo → artifact upsert) more than once against a
 * real database, because that repetition is precisely where the defect lived: each individual
 * step was correct, and the unit tests that mocked `insertArtifact` could not see the loop.
 */
describe("cooling-off embargo across repeated syncs", () => {
  let pool: Pool;

  /** One sync's worth of work for a single version, as `processVersion` does it. */
  async function sync(version: string, versionGroup: string, releasedAt?: Date) {
    const threshold = await getMaxAvailableVersionSort(pool, PKG);
    const versionRow = await insertVersion(pool, {
      package_name: PKG,
      version,
      version_group: versionGroup,
      is_lts: false,
      version_sort: generateSortKey(version),
    });
    const coolingOffUntil = computeCoolingOffUntil(
      { version, releasedAt },
      retention,
      threshold,
      versionRow.discovered_at,
    );
    const artifact = await insertArtifact(pool, {
      version_id: versionRow.id,
      os: "linux",
      arch: "x86-64",
      filename: `tool-${version}.tar.gz`,
      upstream_url: `https://example.test/${version}`,
      cooling_off_until: coolingOffUntil,
    });
    // What the sync service asks next: is this artifact downloadable on this run?
    const queued =
      artifact.status === "pending" &&
      !(artifact.cooling_off_until !== null && artifact.cooling_off_until > new Date());
    return { versionRow, artifact, queued };
  }

  /** Backdate first discovery, standing in for syncs that happened days ago. */
  async function backdateDiscovery(versionId: number, daysAgo: number) {
    await pool.query("UPDATE versions SET discovered_at = $2 WHERE id = $1", [
      versionId,
      new Date(Date.now() - daysAgo * DAY),
    ]);
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await cleanup();
    await pool.end();
  });

  beforeEach(async () => {
    await cleanup();
    await upsertPackage(pool, {
      name: PKG,
      display_name: "cooling off",
      vendor: "test",
      description: null,
      website: null,
      config_hash: "hash",
      enabled: true,
    });
    // Baseline: 1.26.3 is already available, so it is the watermark newer versions are measured
    // against. Without it every version is a bootstrap and nothing is ever embargoed.
    const base = await insertVersion(pool, {
      package_name: PKG,
      version: "1.26.3",
      version_group: "1.26",
      is_lts: false,
      version_sort: generateSortKey("1.26.3"),
    });
    const baseArtifact = await insertArtifact(pool, {
      version_id: base.id,
      os: "linux",
      arch: "x86-64",
      filename: "tool-1.26.3.tar.gz",
      upstream_url: "https://example.test/1.26.3",
      cooling_off_until: null,
    });
    await updateArtifactStatus(pool, baseArtifact.id, {
      status: "available",
      gcs_path: "packages/test/1.26.3",
      file_size: 1,
      checksum: "abc",
      checksum_type: "sha256",
    });
  });

  async function cleanup() {
    await pool.query(
      "DELETE FROM artifacts WHERE version_id IN (SELECT id FROM versions WHERE package_name = $1)",
      [PKG],
    );
    await pool.query("DELETE FROM versions WHERE package_name = $1", [PKG]);
    await pool.query("DELETE FROM packages WHERE name = $1", [PKG]);
  }

  it("holds the embargo end still across repeated syncs of an undownloaded version", async () => {
    const ends: Date[] = [];
    for (let i = 0; i < 3; i++) {
      const { artifact, queued } = await sync("1.27.0", "1.27");
      expect(artifact.status).toBe("pending");
      expect(queued).toBe(false);
      ends.push(artifact.cooling_off_until!);
      await new Promise((r) => setTimeout(r, 5));
    }
    // The watermark cannot advance while 1.27.0 is pending, so this is the exact condition the
    // clock-anchored fallback turned into a permanent embargo.
    expect(await getMaxAvailableVersionSort(pool, PKG)).toBe(generateSortKey("1.26.3"));
    expect(ends[1].getTime()).toBe(ends[0].getTime());
    expect(ends[2].getTime()).toBe(ends[0].getTime());
  });

  it("releases the version for download once the embargo has elapsed", async () => {
    const { versionRow } = await sync("1.27.0", "1.27");
    await backdateDiscovery(versionRow.id, 4);

    const second = await sync("1.27.0", "1.27");
    expect(second.artifact.cooling_off_until).toBeNull();
    expect(second.queued).toBe(true);
  });

  it("corrects an artifact left carrying a clock-anchored embargo end", async () => {
    // A row written by the old code: discovered days ago, but its embargo end was pushed to
    // three days from now on the most recent sync and would be pushed again on the next.
    const { versionRow, artifact } = await sync("1.27.0", "1.27");
    await backdateDiscovery(versionRow.id, 4);
    const stale = new Date(Date.now() + 3 * DAY);
    await pool.query("UPDATE artifacts SET cooling_off_until = $2 WHERE id = $1", [
      artifact.id,
      stale,
    ]);

    const healed = await sync("1.27.0", "1.27");
    expect(healed.artifact.cooling_off_until).toBeNull();
    expect(healed.queued).toBe(true);
  });

  it("still embargoes a genuinely new version against a real upstream release date", async () => {
    const releasedAt = new Date(Date.now() - 1 * DAY);
    const { artifact, queued } = await sync("1.27.0", "1.27", releasedAt);
    expect(queued).toBe(false);
    expect(artifact.cooling_off_until!.getTime()).toBe(releasedAt.getTime() + 3 * DAY);
  });
});
