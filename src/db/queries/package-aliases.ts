import { Pool } from "pg";
import { Queryable } from "../queryable.js";

// ── Shapes ──────────────────────────────────────────────────────────────────

export interface CpePair {
  cpe_vendor: string;
  cpe_product: string;
  is_primary: boolean;
}

export interface AliasRow {
  alias: string;
  source: string;
}

export interface VulnConfigInput {
  packageName: string;
  /** Already-normalized alias strings (lowercase, collapsed ws). */
  aliases: string[];
  cpes: CpePair[];
  osvEcosystem: string | null;
  osvName: string | null;
}

export interface OsvPackageRow {
  package_name: string;
  osv_ecosystem: string;
  osv_name: string;
}

// ── Reconciliation (TOML → DB, boot; plan §2) ───────────────────────────────

/**
 * Reconcile one package's vuln metadata from TOML into the DB, transactionally.
 * `'config'` aliases/cpes are inserted/updated/deleted to match the config;
 * `'learned'` aliases are preserved. Idempotent: two runs with the same input
 * leave identical rows.
 */
export async function reconcilePackageVuln(pool: Pool, input: VulnConfigInput): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Aliases: upsert desired (promoting any matching 'learned' row to 'config'),
    // then drop 'config' rows no longer desired. 'learned' rows survive.
    const desired = [...new Set(input.aliases.filter((a) => a.length > 0))];
    for (const alias of desired) {
      await client.query(
        `INSERT INTO package_aliases (package_name, alias, source)
         VALUES ($1, $2, 'config')
         ON CONFLICT (package_name, alias) DO UPDATE SET source = 'config'`,
        [input.packageName, alias],
      );
    }
    await client.query(
      `DELETE FROM package_aliases
       WHERE package_name = $1 AND source = 'config' AND NOT (alias = ANY($2))`,
      [input.packageName, desired],
    );

    // CPEs: upsert desired, delete the rest.
    for (const cpe of input.cpes) {
      await client.query(
        `INSERT INTO package_cpes (package_name, cpe_vendor, cpe_product, is_primary)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (package_name, cpe_vendor, cpe_product) DO UPDATE SET is_primary = EXCLUDED.is_primary`,
        [input.packageName, cpe.cpe_vendor, cpe.cpe_product, cpe.is_primary],
      );
    }
    await client.query(
      `DELETE FROM package_cpes pc
       WHERE pc.package_name = $1
         AND NOT EXISTS (
           SELECT 1 FROM unnest($2::text[], $3::text[]) AS d(vendor, product)
           WHERE d.vendor = pc.cpe_vendor AND d.product = pc.cpe_product
         )`,
      [
        input.packageName,
        input.cpes.map((c) => c.cpe_vendor),
        input.cpes.map((c) => c.cpe_product),
      ],
    );

    // OSV mapping on the package row.
    await client.query(`UPDATE packages SET osv_ecosystem = $2, osv_name = $3 WHERE name = $1`, [
      input.packageName,
      input.osvEcosystem,
      input.osvName,
    ]);

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

/** Remove all config-sourced vuln metadata for a package (no `[vulnerabilities]` section). */
export async function clearPackageVulnConfig(pool: Pool, packageName: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(
      `DELETE FROM package_aliases WHERE package_name = $1 AND source = 'config'`,
      [packageName],
    );
    await client.query(`DELETE FROM package_cpes WHERE package_name = $1`, [packageName]);
    await client.query(
      `UPDATE packages SET osv_ecosystem = NULL, osv_name = NULL WHERE name = $1`,
      [packageName],
    );
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

// ── Lookups ─────────────────────────────────────────────────────────────────

export async function getPackageAliases(pool: Pool, packageName: string): Promise<AliasRow[]> {
  const { rows } = await pool.query<AliasRow>(
    `SELECT alias, source FROM package_aliases WHERE package_name = $1 ORDER BY alias`,
    [packageName],
  );
  return rows;
}

export async function getPackageCpes(pool: Pool, packageName: string): Promise<CpePair[]> {
  const { rows } = await pool.query<CpePair>(
    `SELECT cpe_vendor, cpe_product, is_primary FROM package_cpes WHERE package_name = $1
     ORDER BY is_primary DESC, cpe_vendor, cpe_product`,
    [packageName],
  );
  return rows;
}

/** Map "vendor:product" → package names that track that pair (NVD ingestion join). */
export async function loadCpeLookup(q: Queryable): Promise<Map<string, string[]>> {
  const { rows } = await q.query<{ package_name: string; cpe_vendor: string; cpe_product: string }>(
    `SELECT package_name, cpe_vendor, cpe_product FROM package_cpes`,
  );
  const map = new Map<string, string[]>();
  for (const r of rows) {
    const key = `${r.cpe_vendor}:${r.cpe_product}`;
    const list = map.get(key) ?? [];
    list.push(r.package_name);
    map.set(key, list);
  }
  return map;
}

/** Distinct CPE pairs across all packages (per-pair NVD backfill). */
export async function listDistinctCpePairs(
  pool: Pool,
): Promise<Array<{ cpe_vendor: string; cpe_product: string }>> {
  const { rows } = await pool.query<{ cpe_vendor: string; cpe_product: string }>(
    `SELECT DISTINCT cpe_vendor, cpe_product FROM package_cpes`,
  );
  return rows;
}

/** Packages with an OSV mapping (OSV cross-check). */
export async function listPackagesWithOsv(pool: Pool): Promise<OsvPackageRow[]> {
  const { rows } = await pool.query<OsvPackageRow>(
    `SELECT name AS package_name, osv_ecosystem, osv_name FROM packages
     WHERE osv_ecosystem IS NOT NULL AND osv_name IS NOT NULL`,
  );
  return rows;
}

export interface AliasSearchRow {
  package_name: string;
  display_name: string;
  alias: string;
}

/**
 * Trigram + prefix candidate fetch for autocomplete. Reranking (token_set_ratio,
 * prefix boost) happens in the caller. `normalizedQuery` must be normalized.
 */
export async function searchAliases(
  pool: Pool,
  normalizedQuery: string,
): Promise<AliasSearchRow[]> {
  const { rows } = await pool.query<AliasSearchRow>(
    `SELECT p.name AS package_name, p.display_name, pa.alias
     FROM package_aliases pa JOIN packages p ON p.name = pa.package_name
     WHERE similarity(pa.alias, $1) > 0.2 OR pa.alias LIKE $2
     ORDER BY similarity(pa.alias, $1) DESC LIMIT 50`,
    [normalizedQuery, `${normalizedQuery}%`],
  );
  return rows;
}

/** Whether a package declares any vuln config (aliases or cpes or osv mapping). */
export async function isPackageTracked(pool: Pool, packageName: string): Promise<boolean> {
  const { rows } = await pool.query<{ tracked: boolean }>(
    `SELECT (
        EXISTS (SELECT 1 FROM package_cpes WHERE package_name = $1)
        OR EXISTS (SELECT 1 FROM package_aliases WHERE package_name = $1 AND source = 'config')
        OR EXISTS (SELECT 1 FROM packages WHERE name = $1 AND osv_ecosystem IS NOT NULL)
     ) AS tracked`,
    [packageName],
  );
  return rows[0]?.tracked ?? false;
}
