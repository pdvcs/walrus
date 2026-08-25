import { Pool } from "pg";
import { PackageRow } from "../../types/db.js";

export async function upsertPackage(
  pool: Pool,
  pkg: Omit<PackageRow, "created_at" | "updated_at">,
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
 *
 * `enabled` applies to the INSERT only — an existing row keeps whatever an
 * operator set. Watch-only packages (`watchlist/*.toml`) pass false: walrus
 * serves no binaries for them, and `enabled = false` is what every serving route
 * already filters on, while the vuln routes ignore it.
 */
export async function ensurePackage(
  pool: Pool,
  pkg: Pick<PackageRow, "name" | "display_name" | "vendor" | "description" | "website">,
  enabled = true,
): Promise<void> {
  await pool.query(
    `INSERT INTO packages (name, display_name, vendor, description, website, config_hash, enabled)
     VALUES ($1, $2, $3, $4, $5, '', $6)
     ON CONFLICT (name) DO UPDATE SET
       display_name = EXCLUDED.display_name,
       vendor       = EXCLUDED.vendor,
       description   = EXCLUDED.description,
       website       = EXCLUDED.website,
       updated_at    = now()`,
    [pkg.name, pkg.display_name, pkg.vendor, pkg.description, pkg.website, enabled],
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
