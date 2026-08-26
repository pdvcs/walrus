import { Pool } from "pg";
import { PackageConfig } from "../types/package-config.js";
import {
  ensurePackage,
  reviveTombstonedPackage,
  markRemovedPackagesNotIn,
} from "../db/queries/packages.js";
import {
  reconcilePackageVuln,
  clearPackageVulnConfig,
  VulnConfigInput,
  CpePair,
} from "../db/queries/package-aliases.js";
import { normalizeName } from "../vuln/normalize.js";
import { log } from "../common/log.js";

/**
 * Resolve a package's `[vulnerabilities]` TOML section into the normalized
 * shape stored in the DB. Returns null when the package has no vuln tracking.
 * Aliases are normalized; the package's own name and display name are always
 * included so the package is findable by its own identity in search/resolution.
 */
export function computeVulnInput(config: PackageConfig): VulnConfigInput | null {
  const v = config.vulnerabilities;
  if (!v) return null;

  const aliasSet = new Set<string>();
  aliasSet.add(normalizeName(config.name));
  aliasSet.add(normalizeName(config.display_name));
  for (const a of v.aliases) aliasSet.add(normalizeName(a));

  const cpes: CpePair[] = v.cpes.map((pair, i) => {
    const [cpe_vendor, cpe_product] = pair.split(":");
    return { cpe_vendor, cpe_product, is_primary: i === 0 };
  });

  return {
    packageName: config.name,
    aliases: [...aliasSet].filter((a) => a.length > 0),
    cpes,
    osvEcosystem: v.osv?.ecosystem ?? null,
    osvName: v.osv?.name ?? null,
  };
}

/**
 * Ensure the package row exists, then reconcile its vuln metadata from config
 * (or clear it if the `[vulnerabilities]` section is absent). Idempotent.
 */
export async function reconcilePackageVulnFromConfig(
  pool: Pool,
  config: PackageConfig,
): Promise<void> {
  await ensurePackage(pool, {
    name: config.name,
    display_name: config.display_name,
    vendor: config.vendor,
    description: config.description ?? null,
    website: config.website ?? null,
  });
  // The TOML exists again (or for the first time): undo any tombstone. Scoped to
  // removed_at IS NOT NULL so an operator's manual disable of a configured package
  // survives reconcile; only an actual removal re-enables on boot.
  await reviveTombstonedPackage(pool, config.name);

  const input = computeVulnInput(config);
  if (input) {
    await reconcilePackageVuln(pool, input);
  } else {
    await clearPackageVulnConfig(pool, config.name);
  }
}

/**
 * Reconcile every configured package's vuln metadata at boot, then close the removal
 * gap (WAL-53): a DB row whose TOML no longer exists used to stay fully live — OSV
 * synced weekly, NVD ingestion attributed to it — because reconcile only ever looked
 * at disk. Tombstone semantics: disable (stops serving/syncing) and clear the vuln
 * config (drops aliases/CPEs/OSV mapping and derived affects), while keeping the row,
 * versions and artifacts so history remains queryable. Hard delete stays an explicit
 * admin action; re-adding the TOML revives the package via reviveTombstonedPackage.
 * Best-effort per package throughout.
 */
export async function reconcileAllPackageVulns(
  pool: Pool,
  configs: PackageConfig[],
): Promise<void> {
  for (const config of configs) {
    try {
      await reconcilePackageVulnFromConfig(pool, config);
    } catch (err) {
      log.error({ package: config.name, err }, "Vuln config reconciliation failed");
    }
  }

  try {
    const removed = await markRemovedPackagesNotIn(
      pool,
      configs.map((c) => c.name),
    );
    for (const name of removed) {
      // Affects rows have no sync left once the OSV mapping and CPEs are gone.
      await clearPackageVulnConfig(pool, name);
      log.warn(
        { package: name },
        "Package TOML removed — tombstoned (disabled, vuln config cleared)",
      );
    }
  } catch (err) {
    log.error({ err }, "Package tombstone reconciliation failed");
  }
}
