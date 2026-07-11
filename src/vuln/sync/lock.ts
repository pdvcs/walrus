import { Pool } from "pg";

export type LockableVulnSource = "nvd" | "kev" | "osv";

export class VulnSyncAlreadyRunningError extends Error {
  constructor(readonly source: LockableVulnSource) {
    super(`vulnerability sync '${source}' is already running`);
    this.name = "VulnSyncAlreadyRunningError";
  }
}

/** Hold a session advisory lock for one source without waiting on an overlapping invocation. */
export async function withVulnSyncLock<T>(
  pool: Pool,
  source: LockableVulnSource,
  run: () => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  let acquired = false;
  try {
    const { rows } = await client.query<{ acquired: boolean }>(
      `SELECT pg_try_advisory_lock(hashtext('walrus:vuln-sync'), hashtext($1)) AS acquired`,
      [source],
    );
    acquired = rows[0]?.acquired ?? false;
    if (!acquired) throw new VulnSyncAlreadyRunningError(source);
    return await run();
  } finally {
    if (acquired) {
      // Session advisory locks release with the connection, so an unlock
      // failure (dead connection) must not mask run()'s error or skip the
      // client release below — that would leak a pool client per failure.
      await client
        .query(`SELECT pg_advisory_unlock(hashtext('walrus:vuln-sync'), hashtext($1))`, [source])
        .catch(() => {});
    }
    client.release();
  }
}

/** Probe whether a source lock is held, releasing it immediately if this call acquires it. */
export async function isVulnSyncRunning(pool: Pool, source: LockableVulnSource): Promise<boolean> {
  const client = await pool.connect();
  try {
    const { rows } = await client.query<{ acquired: boolean }>(
      `SELECT pg_try_advisory_lock(hashtext('walrus:vuln-sync'), hashtext($1)) AS acquired`,
      [source],
    );
    if (!rows[0]?.acquired) return true;
    await client.query(`SELECT pg_advisory_unlock(hashtext('walrus:vuln-sync'), hashtext($1))`, [
      source,
    ]);
    return false;
  } finally {
    client.release();
  }
}
