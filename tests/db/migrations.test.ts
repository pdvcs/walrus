import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

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

  it("creates the vulnerability tables (migration 0002)", async () => {
    const { rows } = await pool.query<{ tablename: string }>(
      `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`,
    );
    const tables = rows.map((r) => r.tablename);
    for (const t of [
      "package_aliases",
      "package_cpes",
      "cves",
      "cve_affects",
      "vuln_sync_state",
      "unresolved_queries",
    ]) {
      expect(tables).toContain(t);
    }
  });

  it("adds the osv mapping columns to packages", async () => {
    const { rows } = await pool.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = 'packages' AND column_name IN ('osv_ecosystem', 'osv_name')`,
    );
    expect(rows.map((r) => r.column_name).sort()).toEqual(["osv_ecosystem", "osv_name"]);
  });

  it("adds separate vulnerability sync outcome timestamps", async () => {
    const { rows } = await pool.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = 'vuln_sync_state'
         AND column_name IN ('last_success_at', 'last_failure_at')`,
    );
    expect(rows.map((row) => row.column_name).sort()).toEqual([
      "last_failure_at",
      "last_success_at",
    ]);
  });

  it("creates the pg_trgm extension and the trigram + affects indexes", async () => {
    const { rows: ext } = await pool.query<{ extname: string }>(
      `SELECT extname FROM pg_extension WHERE extname = 'pg_trgm'`,
    );
    expect(ext).toHaveLength(1);

    const { rows: idx } = await pool.query<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes WHERE schemaname = 'public'`,
    );
    const indexes = idx.map((r) => r.indexname);
    expect(indexes).toContain("idx_pkg_alias_trgm");
    expect(indexes).toContain("idx_cve_affects_pkg");
    expect(indexes).toContain("idx_cve_affects_cve");
  });

  it("enforces the cve_affects NULLS NOT DISTINCT dedupe constraint", async () => {
    const { rows } = await pool.query<{ conname: string }>(
      `SELECT conname FROM pg_constraint WHERE conname = 'cve_affects_dedupe'`,
    );
    expect(rows).toHaveLength(1);
  });

  it("is idempotent — running migrations twice does not error", async () => {
    await expect(runMigrations()).resolves.toBeUndefined();
  });
});
