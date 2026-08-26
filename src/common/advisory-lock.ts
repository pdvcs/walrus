import { Pool } from "pg";

/**
 * Postgres session advisory locks, namespaced by a string pair.
 *
 * Extracted from the vuln-sync lock so package sync can use the same mechanism
 * rather than growing a second, subtly different one. Session-scoped is the
 * important property: the lock is bound to the connection, so a crashed or
 * killed process releases it automatically and cannot strand the next run.
 */
export class AdvisoryLockUnavailableError extends Error {
  constructor(
    readonly namespace: string,
    readonly key: string,
  ) {
    super(`advisory lock '${namespace}:${key}' is already held`);
    this.name = "AdvisoryLockUnavailableError";
  }
}

/**
 * Run `fn` while holding the lock, or throw `AdvisoryLockUnavailableError` if another
 * holder has it. Never waits — an overlapping invocation is reported, not queued.
 */
export async function withAdvisoryLock<T>(
  pool: Pool,
  namespace: string,
  key: string,
  fn: () => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  let acquired = false;
  try {
    const { rows } = await client.query<{ acquired: boolean }>(
      `SELECT pg_try_advisory_lock(hashtext($1), hashtext($2)) AS acquired`,
      [namespace, key],
    );
    acquired = rows[0]?.acquired ?? false;
    if (!acquired) throw new AdvisoryLockUnavailableError(namespace, key);
    return await fn();
  } finally {
    if (acquired) {
      // Session advisory locks release with the connection, so an unlock failure
      // (dead connection) must not mask fn()'s error or skip the client release
      // below — that would leak a pool client per failure.
      await client
        .query(`SELECT pg_advisory_unlock(hashtext($1), hashtext($2))`, [namespace, key])
        .catch(() => {});
    }
    client.release();
  }
}

/** Probe whether a lock is held, releasing it immediately if this call acquires it. */
export async function isAdvisoryLockHeld(
  pool: Pool,
  namespace: string,
  key: string,
): Promise<boolean> {
  const client = await pool.connect();
  try {
    const { rows } = await client.query<{ acquired: boolean }>(
      `SELECT pg_try_advisory_lock(hashtext($1), hashtext($2)) AS acquired`,
      [namespace, key],
    );
    if (!rows[0]?.acquired) return true;
    await client.query(`SELECT pg_advisory_unlock(hashtext($1), hashtext($2))`, [namespace, key]);
    return false;
  } finally {
    client.release();
  }
}
