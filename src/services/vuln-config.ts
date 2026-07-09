import { Pool } from "pg";
import { PackageConfig } from "../types/package-config.js";
import { ensurePackage } from "../db/queries/packages.js";
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

  const input = computeVulnInput(config);
  if (input) {
    await reconcilePackageVuln(pool, input);
  } else {
    await clearPackageVulnConfig(pool, config.name);
  }
}

/** Reconcile every configured package's vuln metadata at boot. Best-effort per package. */
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
}
