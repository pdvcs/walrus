import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../../src/db/client.js";
import { VulnSyncAlreadyRunningError, withVulnSyncLock } from "../../../src/vuln/sync/lock.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

describe("vulnerability sync advisory locks", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  it("rejects same-source overlap without blocking and allows other sources", async () => {
    let release!: () => void;
    let acquired!: () => void;
    const started = new Promise<void>((resolve) => (acquired = resolve));
    const gate = new Promise<void>((resolve) => (release = resolve));
    const first = withVulnSyncLock(pool, "nvd", async () => {
      acquired();
      await gate;
      return "first";
    });
    await started;

    await expect(withVulnSyncLock(pool, "nvd", async () => "second")).rejects.toBeInstanceOf(
      VulnSyncAlreadyRunningError,
    );
    await expect(withVulnSyncLock(pool, "kev", async () => "kev")).resolves.toBe("kev");

    release();
    await expect(first).resolves.toBe("first");
    await expect(withVulnSyncLock(pool, "nvd", async () => "after")).resolves.toBe("after");
  });

  it("does not mask the run error or leak the client when unlock fails", async () => {
    let released = false;
    const client = {
      query: vi.fn(async (sql: string) => {
        if (sql.includes("pg_try_advisory_lock")) return { rows: [{ acquired: true }] };
        throw new Error("connection terminated"); // unlock on a dead connection
      }),
      release: () => {
        released = true;
      },
    };
    const fakePool = { connect: async () => client } as unknown as Pool;

    await expect(
      withVulnSyncLock(fakePool, "nvd", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    expect(released).toBe(true);
  });

  it("releases the lock after a failed run", async () => {
    await expect(
      withVulnSyncLock(pool, "osv", async () => {
        throw new Error("boom");
      }),
    ).rejects.toThrow("boom");
    await expect(withVulnSyncLock(pool, "osv", async () => "recovered")).resolves.toBe("recovered");
  });
});
