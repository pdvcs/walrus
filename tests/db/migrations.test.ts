import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";

const TEST_DB_URL = process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus";

describe("migrations", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  it("creates all expected tables", async () => {
    const { rows } = await pool.query<{ tablename: string }>(
      `SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`,
    );
    const tables = rows.map((r) => r.tablename);
    expect(tables).toContain("packages");
    expect(tables).toContain("versions");
    expect(tables).toContain("artifacts");
    expect(tables).toContain("sync_jobs");
    expect(tables).toContain("admin_actions");
    expect(tables).toContain("migrations"); // created by postgres-migrations
  });

  it("is idempotent — running migrations twice does not error", async () => {
    await expect(runMigrations()).resolves.toBeUndefined();
  });
});
