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
