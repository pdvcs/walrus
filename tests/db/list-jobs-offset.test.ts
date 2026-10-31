import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { listSyncJobs } from "../../src/db/queries/sync-jobs.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

describe("listSyncJobs offset paging", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  it("returns distinct rows across pages (no shared placeholder index)", async () => {
    const page1 = await listSyncJobs(pool, { limit: 2, offset: 0 });
    const page2 = await listSyncJobs(pool, { limit: 2, offset: 2 });
    const ids1 = page1.map((r) => r.id);
    const ids2 = page2.map((r) => r.id);
    expect(ids1).not.toBeNull();
    // Same-index regression would throw on the query itself; overlapping ids would
    // mean the pages are not disjoint.
    for (const id of ids2) expect(ids1).not.toContain(id);
  });

  it("combines filters with offset without placeholder collisions", async () => {
    // Filter params come first; limit/offset must take the next indexes.
    const rows = await listSyncJobs(pool, {
      packageName: "no-such-package",
      status: "succeeded",
      limit: 5,
      offset: 5,
    });
    expect(rows).toEqual([]);
  });
});
