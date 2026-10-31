import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import {
  getDataFreshness,
  getSyncCursor,
  getVulnSyncStatus,
  setSyncState,
} from "../../src/db/queries/vuln-sync-state.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

describe("vulnerability sync state", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM vuln_sync_state WHERE source IN ('nvd-cve', 'cvss')`);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM vuln_sync_state WHERE source IN ('nvd-cve', 'cvss')`);
    await pool.end();
  });

  it("keeps successful freshness and cursor after a later failure", async () => {
    await setSyncState(pool, "nvd-cve", "cursor-ok", true);
    const successfulFreshness = (await getDataFreshness(pool)).nvd_last_sync;
    expect(successfulFreshness).not.toBeNull();

    await setSyncState(pool, "nvd-cve", null, false);

    const freshness = await getDataFreshness(pool);
    const status = await getVulnSyncStatus(pool);
    expect(freshness.nvd_last_sync).toBe(successfulFreshness);
    expect(await getSyncCursor(pool, "nvd-cve")).toBe("cursor-ok");
    expect(status.nvd.last_ok).toBe(false);
    expect(status.nvd.last_success).toBe(successfulFreshness);
    expect(status.nvd.last_failure).not.toBeNull();
    expect(Date.parse(status.nvd.last_attempt!)).toBeGreaterThanOrEqual(
      Date.parse(successfulFreshness!),
    );
  });

  it("records a cvss attempt as in flight without disturbing prior success/failure history", async () => {
    // Success, then failure, then a fresh start marker: the marker must refresh
    // last_attempt and clear last_ok while preserving both timestamps.
    await setSyncState(pool, "cvss", null, true);
    const okAt = (await getVulnSyncStatus(pool)).cvss.last_success;
    await setSyncState(pool, "cvss", null, false);

    const mid = await getVulnSyncStatus(pool);
    expect(mid.cvss.last_ok).toBe(false);
    expect(mid.cvss.last_failure).not.toBeNull();
    const failureAt = mid.cvss.last_failure;

    // `null` = attempt begun, no outcome yet — see setSyncState.
    await setSyncState(pool, "cvss", null, null);

    const status = await getVulnSyncStatus(pool);
    expect(status.cvss.last_ok).toBeNull();
    expect(status.cvss.last_attempt).not.toBeNull();
    expect(Date.parse(status.cvss.last_attempt!)).toBeGreaterThanOrEqual(Date.parse(failureAt!));
    expect(status.cvss.last_success).toBe(okAt); // preserved
    expect(status.cvss.last_failure).toBe(failureAt); // preserved
    expect((await getDataFreshness(pool)).cvss_last_sync).toBe(okAt); // success still counts

    // Completing flips it to a clean success.
    await setSyncState(pool, "cvss", null, true);
    const done = await getVulnSyncStatus(pool);
    expect(done.cvss.last_ok).toBe(true);
    expect(done.cvss.last_failure).toBe(failureAt);
  });
});
