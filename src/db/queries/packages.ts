import { Pool } from "pg";
import { PackageRow } from "../../types/db.js";

export async function upsertPackage(
  pool: Pool,
  // removed_at is deliberately absent: new rows are never tombstones, and a conflict
  // update must not clobber an existing row's removal marker. watch_only is likewise owned
  // by reconcile (ensurePackage); a sync of a served package must not touch it.
  // cve_version_extract is excluded deliberately: it is owned by reconcilePackageVuln
  // (ADR-008), which runs alongside this upsert, so a sync must not reset it to undefined.
  pkg: Omit<
    PackageRow,
    | "created_at"
    | "updated_at"
    | "removed_at"
    | "watch_only"
    | "cve_version_extract"
    | "latest_version"
    | "latest_version_checked_at"
    | "latest_version_error"
    | "osv_synced_at"
    | "osv_ecosystem"
    | "osv_name"
    | "vuln_backfill_completed_at"
  >,
): Promise<PackageRow> {
  const { rows } = await pool.query<PackageRow>(
    `INSERT INTO packages (name, display_name, vendor, description, website, config_hash, enabled)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (name) DO UPDATE SET
       display_name = EXCLUDED.display_name,
       vendor       = EXCLUDED.vendor,
       description  = EXCLUDED.description,
       website      = EXCLUDED.website,
       config_hash  = EXCLUDED.config_hash,
       updated_at   = now()
     RETURNING *`,
    [
      pkg.name,
      pkg.display_name,
      pkg.vendor,
      pkg.description,
      pkg.website,
      pkg.config_hash,
      pkg.enabled,
    ],
  );
  return rows[0];
}

/**
 * Insert a package row if it does not already exist, without clobbering an
 * existing row's config_hash. Used at boot so vuln reconciliation has a package
 * row to reference before any sync has run.
 *
 * `watchOnly` (WAL-54) says which directory the TOML came from and is rewritten on
 * every call, so moving a file between `packages/` and `watchlist/` flips it. A watch
 * row is seeded `enabled = false`: every serving route filters on that, while the vuln
 * routes ignore it. `enabled` is otherwise left alone — an operator's disable survives —
 * except on a kind transition, where it follows the new kind exactly once:
 *   served -> watch: disabled (nothing may serve it any more)
 *   watch -> served: enabled (it was only disabled because it was watch-only)
 */
export async function ensurePackage(
  pool: Pool,
  pkg: Pick<PackageRow, "name" | "display_name" | "vendor" | "description" | "website">,
  { watchOnly = false }: { watchOnly?: boolean } = {},
): Promise<void> {
  await pool.query(
    `INSERT INTO packages (name, display_name, vendor, description, website, config_hash, enabled, watch_only)
     VALUES ($1, $2, $3, $4, $5, '', NOT $6::boolean, $6::boolean)
     ON CONFLICT (name) DO UPDATE SET
       display_name = EXCLUDED.display_name,
       vendor       = EXCLUDED.vendor,
       description  = EXCLUDED.description,
       website      = EXCLUDED.website,
       enabled      = CASE
                        WHEN EXCLUDED.watch_only AND NOT packages.watch_only THEN false
                        WHEN NOT EXCLUDED.watch_only AND packages.watch_only THEN true
                        ELSE packages.enabled
                      END,
       watch_only   = EXCLUDED.watch_only,
       updated_at   = now()`,
    [pkg.name, pkg.display_name, pkg.vendor, pkg.description, pkg.website, watchOnly],
  );
}

export async function getPackage(pool: Pool, name: string): Promise<PackageRow | null> {
  const { rows } = await pool.query<PackageRow>("SELECT * FROM packages WHERE name = $1", [name]);
  return rows[0] ?? null;
}

export async function listPackages(pool: Pool, enabledOnly = false): Promise<PackageRow[]> {
  const { rows } = await pool.query<PackageRow>(
    enabledOnly
      ? "SELECT * FROM packages WHERE enabled = true ORDER BY name"
      : "SELECT * FROM packages ORDER BY name",
  );
  return rows;
}

/**
 * Record a latest-version attempt (WAL-54). A failure keeps the previous good value: a stale
 * "latest" with an error beside it is more useful than none, and the reader decides how stale
 * is too stale from `latest_version_checked_at`.
 */
export async function recordLatestVersion(
  pool: Pool,
  name: string,
  outcome: { version: string } | { error: string },
): Promise<void> {
  if ("version" in outcome) {
    await pool.query(
      `UPDATE packages SET latest_version = $2, latest_version_checked_at = now(),
              latest_version_error = NULL WHERE name = $1`,
      [name, outcome.version],
    );
  } else {
    await pool.query(
      `UPDATE packages SET latest_version_checked_at = now(), latest_version_error = $2
        WHERE name = $1`,
      [name, outcome.error],
    );
  }
}

/** Mark that OSV has been consulted for this package (see migration 0020). */
export async function markOsvSynced(pool: Pool, name: string): Promise<void> {
  await pool.query("UPDATE packages SET osv_synced_at = now() WHERE name = $1", [name]);
}

export interface WatchedPackageRow {
  name: string;
  display_name: string;
  vendor: string;
  osv_ecosystem: string | null;
  osv_name: string | null;
  /** `vendor:product` pairs, primary first. */
  cpes: string[];
  vuln_backfill_completed_at: Date | null;
  vuln_backfill_attempts: number;
  vuln_backfill_last_error: string | null;
  osv_synced_at: Date | null;
  latest_version: string | null;
  latest_version_checked_at: Date | null;
  latest_version_error: string | null;
}

/** Watch-only packages (WAL-54) that are still configured, for the admin listing. */
export async function listWatchedPackages(pool: Pool): Promise<WatchedPackageRow[]> {
  const { rows } = await pool.query<WatchedPackageRow>(
    `SELECT p.name, p.display_name, p.vendor, p.osv_ecosystem, p.osv_name,
            p.vuln_backfill_completed_at, p.vuln_backfill_attempts, p.vuln_backfill_last_error,
            p.osv_synced_at, p.latest_version, p.latest_version_checked_at,
            p.latest_version_error,
            COALESCE((SELECT array_agg(c.cpe_vendor || ':' || c.cpe_product
                                       ORDER BY c.is_primary DESC, c.cpe_vendor, c.cpe_product)
                        FROM package_cpes c WHERE c.package_name = p.name), '{}') AS cpes
       FROM packages p
      WHERE p.watch_only AND p.removed_at IS NULL
      ORDER BY p.name`,
  );
  return rows;
}

export async function setPackageEnabled(pool: Pool, name: string, enabled: boolean): Promise<void> {
  await pool.query("UPDATE packages SET enabled = $2, updated_at = now() WHERE name = $1", [
    name,
    enabled,
  ]);
}

// ── Removal lifecycle (WAL-53) ──────────────────────────────────────────────

/**
 * Tombstone every package whose name is not among `configured` and has not been
 * tombstoned already. Disabling stops serving and syncing; `removed_at` distinguishes
 * a removal from an operator disable or a watch-only row. Returns the names newly
 * marked so the caller can clear their vuln config and log.
 */
export async function markRemovedPackagesNotIn(
  pool: Pool,
  configured: string[],
): Promise<string[]> {
  const { rows } = await pool.query<{ name: string }>(
    `UPDATE packages SET removed_at = now(), enabled = false, updated_at = now()
      WHERE removed_at IS NULL
        AND NOT (name = ANY($1))
      RETURNING name`,
    [configured],
  );
  return rows.map((r) => r.name);
}

/**
 * Undo a tombstone when the package's TOML reappears. Deliberately scoped to
 * `removed_at IS NOT NULL`: reconcile runs at every boot, and an operator's manual
 * disable of a still-configured package must survive it. Only a prior removal flips
 * `enabled` back on — and never for a watch-only row (WAL-54), which stays disabled.
 */
export async function reviveTombstonedPackage(pool: Pool, name: string): Promise<void> {
  await pool.query(
    `UPDATE packages SET enabled = NOT watch_only, removed_at = NULL, updated_at = now()
      WHERE name = $1 AND removed_at IS NOT NULL`,
    [name],
  );
}
