#!/usr/bin/env tsx
/**
 * latest-download-url.ts — Print the download URL(s) for the latest version of a
 * package served by a running walrus instance, and the latest LTS version too if
 * the package has one.
 *
 * Usage:
 *   npm run latest-download-url -- <package> [--os=<os>] [--arch=<arch>] [--base=<url>]
 *
 * --os and --arch default to the current machine's platform/arch, mapped to walrus's
 * os/arch vocabulary (windows|macos|linux, x86-64|arm64) — see PlatformSchema in
 * src/types/package-config.ts.
 *
 * Example:
 *   npm run latest-download-url -- gitwindows --os=windows --arch=x86-64
 *   npm run latest-download-url -- nodejs --base=http://localhost:8080
 */

import os from "node:os";

function currentOs(): string {
  switch (os.platform()) {
    case "darwin":
      return "macos";
    case "win32":
      return "windows";
    default:
      return os.platform();
  }
}

function currentArch(): string {
  switch (os.arch()) {
    case "x64":
      return "x86-64";
    default:
      return os.arch();
  }
}

interface VersionGroup {
  group: string;
  is_lts: boolean;
  latest_available: string | null;
}

interface GroupsResponse {
  package: string;
  groups: VersionGroup[];
}

interface LatestArtifactResponse {
  artifact: {
    download_url: string;
  };
}

function parseArgs(argv: string[]): { _: string[]; [key: string]: string | string[] } {
  const args: { _: string[]; [key: string]: string | string[] } = { _: [] };
  for (const arg of argv) {
    const m = arg.match(/^--([^=]+)=(.*)$/);
    if (m) {
      args[m[1]] = m[2];
    } else {
      args._.push(arg);
    }
  }
  return args;
}

async function fetchLatestUrl(
  base: string,
  packageName: string,
  group: string,
  os?: string,
  arch?: string,
): Promise<string | null> {
  const qs = new URLSearchParams();
  if (os) qs.set("os", os);
  if (arch) qs.set("arch", arch);
  const query = qs.toString() ? `?${qs.toString()}` : "";

  const res = await fetch(
    `${base}/api/v1/packages/${packageName}/versions/${group}/latest${query}`,
  );

  if (res.status === 202) {
    console.error(
      `Package '${packageName}' group '${group}' has no synced artifact yet — sync was triggered, retry shortly.`,
    );
    return null;
  }
  if (res.status === 423) {
    const body = (await res.json()) as { available_at: string };
    console.error(
      `Latest version in group '${group}' for '${packageName}' is cooling off until ${body.available_at}.`,
    );
    return null;
  }
  if (!res.ok) {
    console.error(
      `Failed to get latest artifact for '${packageName}' group '${group}': ${res.status} ${await res.text()}`,
    );
    return null;
  }

  const body = (await res.json()) as LatestArtifactResponse;
  return `${base}${body.artifact.download_url}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const packageName = args._[0];
  if (!packageName) {
    console.error(
      "Usage: latest-download-url.ts <package> [--os=..] [--arch=..] [--base=..]",
    );
    process.exit(1);
  }

  const base = (typeof args.base === "string" ? args.base : "http://localhost:8080").replace(
    /\/+$/,
    "",
  );
  const targetOs = typeof args.os === "string" ? args.os : currentOs();
  const targetArch = typeof args.arch === "string" ? args.arch : currentArch();

  const groupsRes = await fetch(`${base}/api/v1/packages/${packageName}/groups`);
  if (!groupsRes.ok) {
    console.error(
      `Failed to list version groups for '${packageName}': ${groupsRes.status} ${await groupsRes.text()}`,
    );
    process.exit(1);
  }
  const groupsBody = (await groupsRes.json()) as GroupsResponse;
  const groups = groupsBody.groups ?? [];
  const latestGroup = groups[0]?.group;
  if (!latestGroup) {
    console.error(`No version groups found for '${packageName}'`);
    process.exit(1);
  }

  // Groups already come back newest-first overall, so the first LTS-flagged entry
  // (if any) is the latest LTS group — distinct from the overall latest group.
  const latestLtsGroup = groups.find((g) => g.is_lts)?.group;

  const latestUrl = await fetchLatestUrl(base, packageName, latestGroup, targetOs, targetArch);
  if (latestUrl) {
    console.log(`latest: ${latestUrl}`);
  }

  if (latestLtsGroup && latestLtsGroup !== latestGroup) {
    const ltsUrl = await fetchLatestUrl(base, packageName, latestLtsGroup, targetOs, targetArch);
    if (ltsUrl) {
      console.log(`latest LTS: ${ltsUrl}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
