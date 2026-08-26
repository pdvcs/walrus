import { Pool } from "pg";
import {
  AdvisoryLockUnavailableError,
  isAdvisoryLockHeld,
  withAdvisoryLock,
} from "../../common/advisory-lock.js";

export type LockableVulnSource = "nvd" | "kev" | "osv";

const NAMESPACE = "walrus:vuln-sync";

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
  try {
    return await withAdvisoryLock(pool, NAMESPACE, source, run);
  } catch (err) {
    // Only translate *this* lock's contention. An AdvisoryLockUnavailableError raised
    // inside run() belongs to a different lock and must surface unchanged.
    if (
      err instanceof AdvisoryLockUnavailableError &&
      err.namespace === NAMESPACE &&
      err.key === source
    ) {
      throw new VulnSyncAlreadyRunningError(source);
    }
    throw err;
  }
}

/** Probe whether a source lock is held, releasing it immediately if this call acquires it. */
export async function isVulnSyncRunning(pool: Pool, source: LockableVulnSource): Promise<boolean> {
  return isAdvisoryLockHeld(pool, NAMESPACE, source);
}
