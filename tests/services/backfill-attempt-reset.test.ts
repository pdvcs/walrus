import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { MAX_ATTEMPTS, resetBackfillAttempts } from "../../src/services/vuln-backfill-autostart.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

/**
 * WAL-100. Three failed sweeps used to put a package permanently outside self-healing, because
 * `vuln_backfill_attempts` was cleared only by `markBackfillComplete` — by the backfill that
 * could not start. The recovery on record was a psql session against a Cloud SQL instance the
 * deployment deliberately keeps off the public internet.
 *
 * Real database rather than a fake pool: what is being asserted is the SQL — which rows the
 * predicate selects, and which columns it leaves alone — and a stubbed `query` would assert only
 * that a string was passed to it.
 */
const STUCK = "reset-stuck-pkg";
const TRYING = "reset-trying-pkg";
const CLEAN = "reset-clean-pkg";

describe("resetBackfillAttempts (WAL-100)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations(pool);
  });
  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[STUCK, TRYING, CLEAN]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[STUCK, TRYING, CLEAN]]);
    for (const name of [STUCK, TRYING, CLEAN]) {
      await upsertPackage(pool, {
        name,
        display_name: name,
        vendor: "T",
        description: null,
        website: null,
        config_hash: "h",
        enabled: true,
      });
    }
    await pool.query(
      `UPDATE packages SET vuln_backfill_attempts = $2, vuln_backfill_last_error = $3
        WHERE name = $1`,
      [STUCK, MAX_ATTEMPTS, "Cloud Run Job launch failed (403)"],
    );
    await pool.query(`UPDATE packages SET vuln_backfill_attempts = $2 WHERE name = $1`, [
      TRYING,
      MAX_ATTEMPTS - 1,
    ]);
  });

  const read = async (name: string) => {
    const { rows } = await pool.query<{
      attempts: number;
      last_error: string | null;
      cpe_hash: string | null;
      completed_at: Date | null;
    }>(
      `SELECT vuln_backfill_attempts AS attempts, vuln_backfill_last_error AS last_error,
              vuln_backfill_cpe_hash AS cpe_hash, vuln_backfill_completed_at AS completed_at
         FROM packages WHERE name = $1`,
      [name],
    );
    return rows[0];
  };

  it("clears the counter and the error for one named package", async () => {
    expect(await resetBackfillAttempts(pool, STUCK)).toEqual([STUCK]);
    const row = await read(STUCK);
    expect(row.attempts).toBe(0);
    expect(row.last_error).toBeNull();
  });

  it("leaves a package that still has budget alone", async () => {
    // Resetting a package sitting below the ceiling is not a recovery, and counting it as one
    // would inflate the number the operator reads back from the audit entry.
    expect(await resetBackfillAttempts(pool, TRYING)).toEqual([]);
    expect((await read(TRYING)).attempts).toBe(MAX_ATTEMPTS - 1);
  });

  it("resets every exhausted package when no name is given, and only those", async () => {
    const reset = await resetBackfillAttempts(pool);
    expect(reset).toContain(STUCK);
    expect(reset).not.toContain(TRYING);
    expect(reset).not.toContain(CLEAN);
    expect((await read(TRYING)).attempts).toBe(MAX_ATTEMPTS - 1);
    expect((await read(CLEAN)).attempts).toBe(0);
  });

  it("does not touch the sweep's own coverage record", async () => {
    // The counter says "may this be retried"; the hash and timestamp say "what has been covered"
    // (WAL-101). Clearing those here would make the next sweep re-backfill a covered package —
    // an operator asking for a retry has not asserted that the coverage is stale.
    await pool.query(
      `UPDATE packages SET vuln_backfill_cpe_hash = $2, vuln_backfill_completed_at = now()
        WHERE name = $1`,
      [STUCK, "deadbeef"],
    );
    await resetBackfillAttempts(pool, STUCK);
    const row = await read(STUCK);
    expect(row.cpe_hash).toBe("deadbeef");
    expect(row.completed_at).not.toBeNull();
  });

  it("is idempotent — a second call reports nothing rather than failing", async () => {
    expect(await resetBackfillAttempts(pool, STUCK)).toEqual([STUCK]);
    expect(await resetBackfillAttempts(pool, STUCK)).toEqual([]);
  });

  it("reports nothing for a package that does not exist", async () => {
    expect(await resetBackfillAttempts(pool, "no-such-package")).toEqual([]);
  });
});
