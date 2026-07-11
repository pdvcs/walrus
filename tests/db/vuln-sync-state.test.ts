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
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'nvd-cve'`);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'nvd-cve'`);
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
});
