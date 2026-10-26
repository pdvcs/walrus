import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion } from "../../src/db/queries/versions.js";
import { getArtifact, insertArtifact } from "../../src/db/queries/artifacts.js";
import { listWaivedVersions } from "../../src/db/queries/cooling-off-waivers.js";
import { computeCoolingOffUntil } from "../../src/common/retention-window.js";
import {
  CoolingOffWaiverRejectedError,
  createAuditedCoolingOffWaiver,
  revokeAuditedCoolingOffWaiver,
} from "../../src/services/cooling-off-waiver-service.js";
import { PackageConfig } from "../../src/types/package-config.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-waiver-pkg";
const DAY = 86_400_000;
const retention = { versions_per_group: 2, cooling_off_days: 3 } as PackageConfig["retention"];

/**
 * A waiver has to outlive the next sync. `insertArtifact` rewrites `cooling_off_until` from
 * `computeCoolingOffUntil` on every run, so these tests replay that upsert against a real
 * database rather than asserting on the waiver row alone.
 */
describe("cooling-off waivers", () => {
  let pool: Pool;
  let versionId: number;

  async function resync(waived: boolean) {
    return insertArtifact(pool, {
      version_id: versionId,
      os: "linux",
      arch: "x64",
      filename: "tool-1.27.0.tar.gz",
      upstream_url: "https://example.test/tool-1.27.0.tar.gz",
      cooling_off_until: computeCoolingOffUntil(
        { version: "1.27.0", releasedAt: new Date(Date.now() - 1 * DAY) },
        retention,
        null,
        undefined,
        waived,
      ),
    });
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE package_name = $1`, [PKG]);
    await pool.query(
      `DELETE FROM artifacts WHERE version_id IN (SELECT id FROM versions WHERE package_name = $1)`,
      [PKG],
    );
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await upsertPackage(pool, {
      name: PKG,
      display_name: "Test",
      vendor: "Acme",
      description: null,
      website: null,
      config_hash: "abc",
      enabled: true,
    });
    const v = await insertVersion(pool, {
      package_name: PKG,
      version: "1.27.0",
      version_group: "1.27",
      is_lts: false,
      version_sort: "0001.0027.0000",
    });
    versionId = v.id;
    await resync(false);
  });

  const input = { package_name: PKG, version: "1.27.0", reason: "urgent fix", created_by: "ops" };

  it("releases the embargoed artifacts and audits it", async () => {
    expect((await getArtifact(pool, versionId, "linux", "x64"))!.cooling_off_until).not.toBeNull();

    const { waiver, artifacts_released } = await createAuditedCoolingOffWaiver(pool, input);

    expect(artifacts_released).toBe(1);
    expect((await getArtifact(pool, versionId, "linux", "x64"))!.cooling_off_until).toBeNull();
    expect([...(await listWaivedVersions(pool, PKG))]).toEqual(["1.27.0"]);
    const { rows } = await pool.query(
      `SELECT performed_by, version, details FROM admin_actions
        WHERE package_name = $1 AND action_type = 'cooling-off-waived'`,
      [PKG],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ performed_by: "ops", version: "1.27.0" });
    expect(rows[0].details).toMatchObject({ waiver_id: waiver.id, reason: "urgent fix" });
  });

  it("stays released when the next sync recomputes the embargo", async () => {
    await createAuditedCoolingOffWaiver(pool, input);
    const waived = (await listWaivedVersions(pool, PKG)).has("1.27.0");

    const row = await resync(waived);

    expect(row.cooling_off_until).toBeNull();
  });

  it("re-embargoes on the next sync once the waiver is revoked", async () => {
    const { waiver } = await createAuditedCoolingOffWaiver(pool, input);
    await revokeAuditedCoolingOffWaiver(pool, {
      id: waiver.id,
      reason: "mistake",
      revoked_by: "ops",
    });

    const row = await resync((await listWaivedVersions(pool, PKG)).has("1.27.0"));

    expect(row.cooling_off_until).not.toBeNull();
    expect(
      await revokeAuditedCoolingOffWaiver(pool, { id: waiver.id, reason: "x", revoked_by: "ops" }),
    ).toBeNull();
  });

  it("rejects an unknown version and one that is not embargoed", async () => {
    await expect(
      createAuditedCoolingOffWaiver(pool, { ...input, version: "9.9.9" }),
    ).rejects.toMatchObject({ code: "version-not-found" });

    await createAuditedCoolingOffWaiver(pool, input);
    await expect(createAuditedCoolingOffWaiver(pool, input)).rejects.toBeInstanceOf(
      CoolingOffWaiverRejectedError,
    );
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM cooling_off_waivers WHERE package_name = $1`,
      [PKG],
    );
    expect(rows[0].n).toBe(1);
  });
});
