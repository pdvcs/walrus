import crypto from "crypto";
import { Pool } from "pg";
import { log } from "../common/log.js";

/**
 * Autonomous per-package historical backfill (WAL-37, ADR-003 commitment 2).
 *
 * Incremental NVD sync walks CVEs by `lastModStartDate`, so a package whose CPE pairs are
 * declared after the first backfill can never acquire its historical CVEs from it. Until
 * this existed, closing that gap depended on someone reading an operator hint — and the hint
 * only fired when `cve_affects` was globally empty, so it never fired at all for a package
 * added later. The package was served with CVE history that was never ingested.
 */

/** Attempts after which a package stops being retried automatically. */
export const MAX_ATTEMPTS = 3;

export interface PendingBackfill {
  package_name: string;
  cpe_hash: string;
  attempts: number;
}

/**
 * A stable fingerprint of the package's CPE pairs. Comparing this rather than a bare
 * timestamp is what lets a *newly added* pair on an already-covered package be detected:
 * the set changed, so the recorded coverage no longer describes it.
 *
 * This is the *only* place a CPE set becomes a digest. It used to have a twin expressed in
 * SQL, inside the sweep's selection query, and the two disagreed on any pair whose ordering
 * depends on collation: Postgres sorts by the database's collation, and glibc's `en_US.UTF8`
 * ignores punctuation at the primary weight, while `Array.prototype.sort` compares UTF-16
 * code units. `git-scm:git` and `git:git` order one way in Cloud SQL and the other way here,
 * so a package holding both could never match its own marker and was re-backfilled on every
 * sweep forever (WAL-101). Keep the digest single-sourced.
 */
export function hashCpePairs(pairs: Array<{ cpe_vendor: string; cpe_product: string }>): string {
  const canonical = [...new Set(pairs.map((p) => `${p.cpe_vendor}:${p.cpe_product}`))]
    .sort()
    .join("|");
  return crypto.createHash("sha256").update(canonical).digest("hex");
}

/**
 * Packages whose current CPE set has never been backfilled, fewest attempts first.
 *
 * Deliberately keyed on the CPE hash rather than on whether any `cve_affects` rows exist: a
 * package can legitimately have zero CVEs, and treating that as "needs backfill" would
 * re-walk it on every sweep forever.
 *
 * The query returns pairs and the stored marker; the comparison happens in TypeScript so that
 * both sides of it run through `hashCpePairs`. Filtering in SQL would mean recomputing the
 * digest there — see the note on `hashCpePairs` for what that cost.
 */
export async function findPackagesNeedingBackfill(pool: Pool): Promise<PendingBackfill[]> {
  const { rows } = await pool.query<{
    package_name: string;
    cpe_vendor: string;
    cpe_product: string;
    stored_hash: string | null;
    attempts: number;
  }>(
    `SELECT DISTINCT p.name AS package_name,
            c.cpe_vendor,
            c.cpe_product,
            p.vuln_backfill_cpe_hash AS stored_hash,
            p.vuln_backfill_attempts AS attempts
       FROM packages p
       JOIN package_cpes c ON c.package_name = p.name
      WHERE p.vuln_backfill_attempts < $1`,
    [MAX_ATTEMPTS],
  );

  const byPackage = new Map<
    string,
    {
      pairs: Array<{ cpe_vendor: string; cpe_product: string }>;
      stored: string | null;
      attempts: number;
    }
  >();
  for (const row of rows) {
    const entry = byPackage.get(row.package_name) ?? {
      pairs: [],
      stored: row.stored_hash,
      attempts: row.attempts,
    };
    entry.pairs.push({ cpe_vendor: row.cpe_vendor, cpe_product: row.cpe_product });
    byPackage.set(row.package_name, entry);
  }

  return [...byPackage.entries()]
    .map(([package_name, { pairs, stored, attempts }]) => ({
      package_name,
      cpe_hash: hashCpePairs(pairs),
      attempts,
      stored,
    }))
    .filter((entry) => entry.stored !== entry.cpe_hash)
    .sort((a, b) => a.attempts - b.attempts || (a.package_name < b.package_name ? -1 : 1))
    .map(({ package_name, cpe_hash, attempts }) => ({ package_name, cpe_hash, attempts }));
}

/** Record that this package's current CPE set has been covered. */
export async function markBackfillComplete(
  pool: Pool,
  packageName: string,
  cpeHash: string,
): Promise<void> {
  await pool.query(
    `UPDATE packages
        SET vuln_backfill_cpe_hash = $2,
            vuln_backfill_completed_at = now(),
            vuln_backfill_attempts = 0,
            vuln_backfill_last_error = NULL
      WHERE name = $1`,
    [packageName, cpeHash],
  );
}

/**
 * Count an attempt before launching, not after. A launch that never reports back — the
 * process dies, the Cloud Run Job is evicted — must still consume an attempt, or a package
 * that fails that way is retried forever.
 */
export async function recordBackfillAttempt(pool: Pool, packageName: string): Promise<void> {
  await pool.query(
    `UPDATE packages
        SET vuln_backfill_attempts = vuln_backfill_attempts + 1,
            vuln_backfill_last_error = NULL
      WHERE name = $1`,
    [packageName],
  );
}

/** Attach a reason to the attempt already counted — never a second increment. */
export async function recordBackfillError(
  pool: Pool,
  packageName: string,
  error: string,
): Promise<void> {
  await pool.query(`UPDATE packages SET vuln_backfill_last_error = $2 WHERE name = $1`, [
    packageName,
    error,
  ]);
}

export interface AutoBackfillResult {
  pending: number;
  started: string[];
  deferred: string[];
  failed: Array<{ package: string; error: string }>;
}

export interface AutoBackfillDeps {
  startVulnBackfill: (
    since?: string,
    packageName?: string,
  ) => Promise<{ job?: { id: string }; alreadyRunning?: boolean }>;
}

/**
 * Start a targeted backfill for each package missing coverage.
 *
 * One at a time by design: a backfill is a Cloud Run Job walking one NVD request per CPE
 * pair, and the single-active-job constraint would reject the rest anyway. Everything not
 * started this sweep is reported as deferred and picked up by the next one.
 */
export async function autoBackfillPendingPackages(
  pool: Pool,
  deps: AutoBackfillDeps,
): Promise<AutoBackfillResult> {
  const pending = await findPackagesNeedingBackfill(pool);
  const result: AutoBackfillResult = {
    pending: pending.length,
    started: [],
    deferred: [],
    failed: [],
  };

  for (const entry of pending) {
    if (result.started.length > 0) {
      // Only one backfill can be active; do not queue work that will be refused.
      result.deferred.push(entry.package_name);
      continue;
    }
    try {
      await recordBackfillAttempt(pool, entry.package_name);
      const started = await deps.startVulnBackfill(undefined, entry.package_name);
      if (started.alreadyRunning) {
        // Contention is not a failure and must not consume the retry budget.
        await pool.query(
          `UPDATE packages SET vuln_backfill_attempts = GREATEST(vuln_backfill_attempts - 1, 0)
            WHERE name = $1`,
          [entry.package_name],
        );
        result.deferred.push(entry.package_name);
        continue;
      }
      log.info(
        { package: entry.package_name, jobId: started.job?.id },
        "Started autonomous CVE backfill for newly tracked package",
      );
      result.started.push(entry.package_name);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      // The attempt was already counted before the launch; only record why it failed.
      await recordBackfillError(pool, entry.package_name, message).catch(() => {});
      if (entry.attempts + 1 >= MAX_ATTEMPTS) {
        log.error(
          { package: entry.package_name, attempts: entry.attempts + 1, err: error },
          "Package exhausted automatic CVE backfill retries",
        );
      }
      log.error({ package: entry.package_name, err: error }, "Autonomous CVE backfill failed");
      result.failed.push({ package: entry.package_name, error: message });
    }
  }

  return result;
}
