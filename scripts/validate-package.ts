#!/usr/bin/env tsx
/**
 * validate-package.ts — Dry-run validator for package TOML configs.
 *
 * Usage:
 *   npm run validate                        # validate all packages/*.toml
 *   npm run validate -- packages/uv.toml   # validate a single file
 */

import fs from "fs";
import path from "path";
import { loadPackageConfig, loadAllPackages } from "../src/services/package-registry.js";
import { getStrategy } from "../src/discovery/index.js";
import { sortVersionsDesc } from "../src/common/version-utils.js";
import { PackageConfig } from "../src/types/package-config.js";
import { DiscoveredVersion } from "../src/discovery/types.js";
import { computeVulnInput } from "../src/services/vuln-config.js";

const PACKAGES_DIR = path.join(process.cwd(), "packages");
const SPOT_CHECK_PLATFORM = { os: "linux", arch: "x86-64" } as const;

// ── ANSI colours ─────────────────────────────────────────────────────────────

const c = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

// ── Retention plan ────────────────────────────────────────────────────────────

interface RetentionPlan {
  kept: string[];
  pruned: string[];
}

function computeRetentionPlan(versions: DiscoveredVersion[], config: PackageConfig): RetentionPlan {
  const byGroup = new Map<string, string[]>();

  for (const v of versions) {
    const group = v.versionGroup;
    if (!byGroup.has(group)) byGroup.set(group, []);
    byGroup.get(group)!.push(v.version);
  }

  // Sort groups newest-first using the same numeric sort applied to versions
  const sortedGroups = sortVersionsDesc([...byGroup.keys()]);

  const kept: string[] = [];
  const pruned: string[] = [];
  const limit = config.retention.versions_per_group;
  const groupsToKeep = config.retention.groups_to_keep;

  for (let i = 0; i < sortedGroups.length; i++) {
    const group = sortedGroups[i];
    const sorted = sortVersionsDesc(byGroup.get(group)!);
    if (groupsToKeep !== undefined && i >= groupsToKeep) {
      pruned.push(...sorted);
    } else {
      kept.push(...sorted.slice(0, limit));
      pruned.push(...sorted.slice(limit));
    }
  }

  return { kept, pruned };
}

// ── HEAD request helper ───────────────────────────────────────────────────────

interface HeadResult {
  ok: boolean;
  status?: number;
  contentLength?: number;
  error?: string;
}

async function headRequest(url: string): Promise<HeadResult> {
  try {
    const response = await fetch(url, { method: "HEAD", signal: AbortSignal.timeout(10_000) });
    const cl = response.headers.get("content-length");
    return {
      ok: response.ok,
      status: response.status,
      contentLength: cl ? parseInt(cl, 10) : undefined,
    };
  } catch (err) {
    return { ok: false, error: String(err) };
  }
}

// ── Single package validation ─────────────────────────────────────────────────

async function validatePackage(filePath: string): Promise<boolean> {
  const shortName = path.relative(process.cwd(), filePath);
  console.log(c.bold(`\nValidating ${shortName}...`));

  let config: PackageConfig;
  try {
    config = loadPackageConfig(filePath);
    console.log(`  ${c.green("✓")} TOML parses and validates against schema`);
  } catch (err) {
    console.log(
      `  ${c.red("✗")} Schema validation failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }

  // Vulnerability metadata (plan §2) — static config, printed before network discovery.
  const vulnInput = computeVulnInput(config);
  if (vulnInput) {
    const cpeStr =
      vulnInput.cpes.length > 0
        ? vulnInput.cpes
            .map(
              (cpe) => `${cpe.cpe_vendor}:${cpe.cpe_product}${cpe.is_primary ? " (primary)" : ""}`,
            )
            .join(", ")
        : c.dim("none (OSV-only)");
    const osvStr = vulnInput.osvEcosystem
      ? `${vulnInput.osvEcosystem}/${vulnInput.osvName}`
      : c.dim("none");
    console.log(`  ${c.green("✓")} Vulnerability tracking enabled`);
    console.log(`    CPE pairs: ${cpeStr}`);
    console.log(`    OSV: ${osvStr}`);
    console.log(`    Aliases (${vulnInput.aliases.length}): ${vulnInput.aliases.join(", ")}`);
  } else {
    console.log(
      `  ${c.dim("○")} ${c.dim("No [vulnerabilities] section — vuln tracking disabled")}`,
    );
  }

  let versions: DiscoveredVersion[];
  try {
    const strategy = getStrategy(config);
    versions = await strategy.discoverVersions(config);

    const versionStrings = versions.map((v) => v.version);
    const preview = versionStrings.slice(0, 6).join(", ");
    const more = versionStrings.length > 6 ? ` ... (+${versionStrings.length - 6} more)` : "";
    console.log(`  ${c.green("✓")} Discovery: ${config.discovery.type}`);
    console.log(`    Found ${versions.length} version(s): ${preview}${more}`);
  } catch (err) {
    console.log(
      `  ${c.red("✗")} Discovery failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return false;
  }

  // Spot-check artifact URL for the newest version on linux/x86-64 (or first available platform)
  const warnings: string[] = [];
  const newestVersion = versions[0]; // strategies return newest first (or we sort below)
  if (newestVersion) {
    const artKey = `${SPOT_CHECK_PLATFORM.os}/${SPOT_CHECK_PLATFORM.arch}`;
    const art = newestVersion.artifacts.get(artKey) ?? [...newestVersion.artifacts.values()][0];

    if (art) {
      console.log(
        `  ${c.green("✓")} Artifact URL resolution (spot-check: ${newestVersion.version} ${artKey})`,
      );
      console.log(`    URL: ${c.dim(art.url)}`);

      const head = await headRequest(art.url);
      if (head.ok) {
        const size = head.contentLength ? ` ${(head.contentLength / 1_048_576).toFixed(1)} MB` : "";
        console.log(`    HEAD request: ${c.green(`${head.status} OK`)}${size}`);
      } else {
        const detail = head.error ?? `HTTP ${head.status}`;
        warnings.push(`${newestVersion.version} ${artKey}: HEAD request failed (${detail})`);
        console.log(`    HEAD request: ${c.yellow(`${head.status ?? "error"}`)} — ${detail}`);
      }
    } else {
      warnings.push(`${newestVersion.version}: no artifacts resolved for any platform`);
    }
  }

  // Retention plan
  const plan = computeRetentionPlan(versions, config);
  console.log(
    `  ${c.green("✓")} Retention: would keep ${plan.kept.length} version(s), prune ${plan.pruned.length}`,
  );
  if (plan.kept.length > 0) {
    console.log(
      `    Would keep: ${plan.kept.slice(0, 4).join(", ")}${plan.kept.length > 4 ? "..." : ""}`,
    );
  }
  if (plan.pruned.length > 0) {
    console.log(
      `    Would prune: ${plan.pruned.slice(0, 4).join(", ")}${plan.pruned.length > 4 ? "..." : ""}`,
    );
  }

  if (warnings.length > 0) {
    console.log(`\n  ${c.yellow(`${warnings.length} warning(s):`)}`);
    for (const w of warnings) {
      console.log(`  ${c.yellow("!")} ${w}`);
    }
  }

  return true;
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  let filePaths: string[];

  if (args.length > 0) {
    filePaths = args.map((a) => path.resolve(a));
    for (const fp of filePaths) {
      if (!fs.existsSync(fp)) {
        console.error(c.red(`File not found: ${fp}`));
        process.exit(1);
      }
    }
  } else {
    const { configs, errors } = loadAllPackages(PACKAGES_DIR);

    if (errors.length > 0) {
      console.log(c.red(`\nFailed to load ${errors.length} package config(s):`));
      for (const e of errors) {
        console.log(`  ${c.red("✗")} ${path.relative(process.cwd(), e.filePath)}: ${e.error}`);
      }
    }

    filePaths = configs.map((c) => c.filePath);
    if (filePaths.length === 0) {
      console.log(c.yellow("No package configs found in packages/"));
      process.exit(0);
    }
  }

  let allPassed = true;
  for (const fp of filePaths) {
    const ok = await validatePackage(fp);
    if (!ok) allPassed = false;
  }

  console.log("");
  if (allPassed) {
    console.log(c.green(`✓ All ${filePaths.length} package config(s) validated successfully`));
    process.exit(0);
  } else {
    console.log(c.red(`✗ Some package configs have errors`));
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(c.red("Unexpected error:"), err);
  process.exit(1);
});
