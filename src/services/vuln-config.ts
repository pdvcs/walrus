import { Pool } from "pg";
import { PackageConfig, VulnerabilitiesConfig } from "../types/package-config.js";
import { WatchConfig } from "../types/watch-config.js";
import { loadAllPackages } from "./package-registry.js";
import { loadAllWatchConfigs } from "./watch-registry.js";
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
 * The identity + vuln fields shared by a served `PackageConfig` and a watch-only
 * `WatchConfig`. Everything below operates on this common shape so both kinds of
 * TOML reconcile through one code path.
 */
export interface VulnTrackableConfig {
  name: string;
  display_name: string;
  vendor: string;
  description?: string;
  website?: string;
  vulnerabilities?: VulnerabilitiesConfig;
}

/**
 * Resolve a package's `[vulnerabilities]` TOML section into the normalized
 * shape stored in the DB. Returns null when the package has no vuln tracking.
 * Aliases are normalized; the package's own name and display name are always
 * included so the package is findable by its own identity in search/resolution.
 */
export function computeVulnInput(config: VulnTrackableConfig): VulnConfigInput | null {
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
 *
 * `enabled` seeds the package row only when it does not yet exist — see
 * `ensurePackage`. Watch-only entries pass false so they never reach the serving
 * routes.
 */
export async function reconcilePackageVulnFromConfig(
  pool: Pool,
  config: VulnTrackableConfig,
  enabled = true,
): Promise<void> {
  await ensurePackage(
    pool,
    {
      name: config.name,
      display_name: config.display_name,
      vendor: config.vendor,
      description: config.description ?? null,
      website: config.website ?? null,
    },
    enabled,
  );

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

/**
 * Reconcile every `watchlist/*.toml` entry at boot. Same path as served
 * packages, but the package row is seeded disabled so nothing tries to serve it.
 * Best-effort per package.
 */
export async function reconcileAllWatchVulns(pool: Pool, configs: WatchConfig[]): Promise<void> {
  for (const config of configs) {
    try {
      await reconcilePackageVulnFromConfig(pool, config, false);
    } catch (err) {
      log.error({ package: config.name, err }, "Watch config reconciliation failed");
    }
  }
}

/**
 * Reconcile every vuln-tracked definition on disk — both served `packages/*.toml`
 * and watch-only `watchlist/*.toml`. Standalone entrypoints (the backfill script,
 * the backfill job) call this so they are self-sufficient on a fresh database
 * without booting the app.
 */
export async function reconcileAllVulnConfigsFromDisk(pool: Pool): Promise<void> {
  await reconcileAllPackageVulns(
    pool,
    loadAllPackages().configs.map((entry) => entry.config),
  );
  await reconcileAllWatchVulns(
    pool,
    loadAllWatchConfigs().configs.map((entry) => entry.config),
  );
}
