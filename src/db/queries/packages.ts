import { Pool } from "pg";
import { PackageRow } from "../../types/db.js";

export async function upsertPackage(
  pool: Pool,
  // removed_at is deliberately absent: new rows are never tombstones, and a conflict
  // update must not clobber an existing row's removal marker.
  // cve_version_extract is excluded deliberately: it is owned by reconcilePackageVuln
  // (ADR-008), which runs alongside this upsert, so a sync must not reset it to undefined.
  pkg: Omit<PackageRow, "created_at" | "updated_at" | "removed_at" | "cve_version_extract">,
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
 * existing row's config_hash/enabled. Used at boot so vuln reconciliation has a
 * package row to reference before any sync has run.
 */
export async function ensurePackage(
  pool: Pool,
  pkg: Pick<PackageRow, "name" | "display_name" | "vendor" | "description" | "website">,
): Promise<void> {
  await pool.query(
    `INSERT INTO packages (name, display_name, vendor, description, website, config_hash, enabled)
     VALUES ($1, $2, $3, $4, $5, '', true)
     ON CONFLICT (name) DO UPDATE SET
       display_name = EXCLUDED.display_name,
       vendor       = EXCLUDED.vendor,
       description   = EXCLUDED.description,
       website       = EXCLUDED.website,
       updated_at    = now()`,
    [pkg.name, pkg.display_name, pkg.vendor, pkg.description, pkg.website],
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
 * `enabled` back on.
 */
export async function reviveTombstonedPackage(pool: Pool, name: string): Promise<void> {
  await pool.query(
    `UPDATE packages SET enabled = true, removed_at = NULL, updated_at = now()
      WHERE name = $1 AND removed_at IS NOT NULL`,
    [name],
  );
}
