import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pool, runMigrations } from "../../src/db/client.js";
import { getMetricsSnapshot } from "../../src/services/metrics-snapshot.js";

const PACKAGE = "metrics-snapshot-fixture";

async function cleanup(): Promise<void> {
  await pool.query("DELETE FROM versions WHERE package_name = $1", [PACKAGE]);
  await pool.query("DELETE FROM sync_jobs WHERE package_name = $1", [PACKAGE]);
  await pool.query("DELETE FROM packages WHERE name = $1", [PACKAGE]);
}

describe("metrics database snapshot", () => {
  beforeAll(async () => {
    await runMigrations();
    await cleanup();
  });

  afterAll(cleanup);

  it("aggregates catalogue, sync, cooling-off, and latest blocking state", async () => {
    await pool.query(
      `INSERT INTO packages (name, display_name, vendor, config_hash, enabled)
       VALUES ($1, $1, 'Test', 'metrics-test', true)`,
      [PACKAGE],
    );
    const version = await pool.query<{ id: number }>(
      `INSERT INTO versions (package_name, version, version_group, version_sort)
       VALUES ($1, '1.0.0', '1', '0001.0000.0000') RETURNING id`,
      [PACKAGE],
    );
    const job = await pool.query<{ id: number }>(
      `INSERT INTO sync_jobs
         (package_name, trigger_type, status, artifacts_queued, artifacts_downloaded,
          artifacts_failed, started_at, completed_at)
       VALUES ($1, 'scheduled', 'completed', 2, 1, 1,
               now() - interval '10 seconds', now())
       RETURNING id`,
      [PACKAGE],
    );
    await pool.query(
      `INSERT INTO artifacts
         (version_id, os, arch, filename, upstream_url, status, file_size, sync_job_id)
       VALUES ($1, 'linux', 'x86-64', 'fixture.tgz', 'https://example.test/fixture',
               'available', 1234, $2)`,
      [version.rows[0].id, job.rows[0].id],
    );
    await pool.query(
      `INSERT INTO artifacts
         (version_id, os, arch, filename, upstream_url, status, cooling_off_until, sync_job_id)
       VALUES ($1, 'mac', 'aarch64', 'fixture.zip', 'https://example.test/fixture',
               'pending', now() + interval '1 day', $2)`,
      [version.rows[0].id, job.rows[0].id],
    );
    await pool.query(
      `INSERT INTO version_availability_events
         (package_name, version, status, source, trigger_type)
       VALUES ($1, '1.0.0', 'blocked', 'test', 'test'),
              ($1, '1.0.0', 'available', 'test', 'test'),
              ($1, '1.0.0', 'blocked', 'test', 'test'),
              ($1, '0.9.0', 'blocked', 'test', 'test')`,
      [PACKAGE],
    );

    const snapshot = await getMetricsSnapshot(pool, { autoBackfillEnabled: true });

    expect(snapshot.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          package_name: PACKAGE,
          status: "available",
          count: 1,
          stored_bytes: 1234,
        }),
        expect.objectContaining({
          package_name: PACKAGE,
          status: "cooling_off",
          count: 1,
        }),
      ]),
    );
    expect(snapshot.packageSyncs).toContainEqual(
      expect.objectContaining({
        package_name: PACKAGE,
        running: 0,
        latest_status: "completed",
        latest_trigger: "scheduled",
        artifacts_queued: 2,
        artifacts_downloaded: 1,
        artifacts_failed: 1,
      }),
    );
    expect(snapshot.blockedVersions).toContainEqual({ package_name: PACKAGE, count: 1 });
  });
});
