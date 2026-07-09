import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  createSyncJob,
  updateSyncJob,
  getSyncJob,
  getRecentSyncJob,
  listSyncJobs,
} from "../../src/db/queries/sync-jobs.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-syncjobs-pkg";
const OTHER_PKG = "test-syncjobs-other-pkg";

describe("sync-jobs queries", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE package_name = ANY($1)`, [[PKG, OTHER_PKG]]);
    await pool.query(`DELETE FROM sync_jobs WHERE package_name = ANY($1)`, [[PKG, OTHER_PKG]]);
    await pool.query(
      `DELETE FROM artifacts WHERE version_id IN (SELECT id FROM versions WHERE package_name = ANY($1))`,
      [[PKG, OTHER_PKG]],
    );
    await pool.query(`DELETE FROM versions WHERE package_name = ANY($1)`, [[PKG, OTHER_PKG]]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, OTHER_PKG]]);

    await upsertPackage(pool, {
      name: PKG,
      display_name: "Test",
      vendor: "Acme",
      description: null,
      website: null,
      config_hash: "abc",
      enabled: true,
    });
  });

  it("creates a sync job with running status", async () => {
    const job = await createSyncJob(pool, PKG, "scheduled");
    expect(job.id).toBeGreaterThan(0);
    expect(job.status).toBe("running");
    expect(job.trigger_type).toBe("scheduled");
    expect(job.versions_found).toBe(0);
  });

  it("updates sync job with completion data", async () => {
    const job = await createSyncJob(pool, PKG, "admin");
    const updated = await updateSyncJob(pool, job.id, {
      status: "completed",
      versions_found: 5,
      artifacts_queued: 25,
      completed_at: new Date(),
    });
    expect(updated!.status).toBe("completed");
    expect(updated!.versions_found).toBe(5);
    expect(updated!.artifacts_queued).toBe(25);
    expect(updated!.completed_at).not.toBeNull();
  });

  it("updates sync job with failure", async () => {
    const job = await createSyncJob(pool, PKG, "on-demand");
    const updated = await updateSyncJob(pool, job.id, {
      status: "failed",
      error_message: "API rate limit exceeded",
      completed_at: new Date(),
    });
    expect(updated!.status).toBe("failed");
    expect(updated!.error_message).toBe("API rate limit exceeded");
  });

  it("getSyncJob retrieves by id", async () => {
    const job = await createSyncJob(pool, PKG, "scheduled");
    const fetched = await getSyncJob(pool, job.id);
    expect(fetched!.id).toBe(job.id);
  });

  it("getRecentSyncJob returns null when no recent completed job", async () => {
    await createSyncJob(pool, PKG, "scheduled");
    // Job is still 'running', not 'completed'
    const recent = await getRecentSyncJob(pool, PKG, 30);
    expect(recent).toBeNull();
  });

  it("getRecentSyncJob returns a recently completed job", async () => {
    const job = await createSyncJob(pool, PKG, "scheduled");
    await updateSyncJob(pool, job.id, { status: "completed", completed_at: new Date() });

    const recent = await getRecentSyncJob(pool, PKG, 30);
    expect(recent).not.toBeNull();
    expect(recent!.id).toBe(job.id);
  });

  it("listSyncJobs filters by package and status", async () => {
    await upsertPackage(pool, {
      name: OTHER_PKG,
      display_name: "Other",
      vendor: "X",
      description: null,
      website: null,
      config_hash: "xyz",
      enabled: true,
    });

    const j1 = await createSyncJob(pool, PKG, "scheduled");
    await createSyncJob(pool, OTHER_PKG, "admin");
    await updateSyncJob(pool, j1.id, { status: "completed", completed_at: new Date() });

    const allJobs = await listSyncJobs(pool);
    expect(allJobs.length).toBeGreaterThanOrEqual(2);

    const testPkgJobs = await listSyncJobs(pool, { packageName: PKG });
    expect(testPkgJobs.every((j) => j.package_name === PKG)).toBe(true);

    const completedJobs = await listSyncJobs(pool, { status: "completed" });
    expect(completedJobs.every((j) => j.status === "completed")).toBe(true);
  });
});
