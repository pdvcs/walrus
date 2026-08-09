import { PackageConfig } from "../types/package-config.js";
import { generateSortKey } from "./version-utils.js";

/**
 * The minimum a version must expose to be placed in a retention window. Kept structural so the
 * discovery strategies (which work with pre-artifact candidates) and the sync service (which works
 * with fully resolved DiscoveredVersions) can share one implementation instead of drifting copies.
 */
export interface RetainableVersion {
  version: string;
  versionGroup: string;
  releasedAt?: Date;
}

/**
 * The release embargo for a version, or null when it may be served immediately.
 *
 * Single source of truth for the retention window (which versions to keep), the artifact rows
 * (which downloads to defer), and `npm run validate` (what it reports) — they must agree, or the
 * window keeps a version the download step never fetches.
 */
export function computeCoolingOffUntil(
  version: Pick<RetainableVersion, "version" | "releasedAt">,
  retention: PackageConfig["retention"],
  coolingOffThreshold: string | null,
): Date | null {
  const coolingOffDays = retention.cooling_off_days;
  if (!coolingOffDays || coolingOffDays <= 0) return null;

  if (version.releasedAt) {
    // Upstream release date available — use it as anchor regardless of bootstrap.
    // If the version was released recently enough that cooling off hasn't elapsed, block it.
    const candidate = new Date(version.releasedAt.getTime() + coolingOffDays * 86_400_000);
    return candidate > new Date() ? candidate : null;
  }
  if (coolingOffThreshold !== null && generateSortKey(version.version) > coolingOffThreshold) {
    // No upstream date — fall back to threshold-based logic: only block versions
    // discovered for the first time above the pre-sync watermark.
    return new Date(Date.now() + coolingOffDays * 86_400_000);
  }
  return null;
}

/**
 * The versions to hold: the newest `groups_to_keep` groups, and within each, `versions_per_group`
 * *servable* versions plus every version still inside its release embargo.
 *
 * The embargoed ones are retained on top of the quota rather than against it — counting them would
 * let each new release displace the fallback users need while it cools off, leaving only
 * versions_per_group - 1 downloadable for the length of the embargo.
 *
 * Three call sites must agree on this, or versions fall through the gaps between them: discovery
 * (which versions get their artifact URLs resolved), the sync window (which versions get rows), and
 * `listVersionsOlderThanInGroup` (which versions get pruned).
 */
export function selectRetentionWindow<T extends RetainableVersion>(
  versions: T[],
  retention: PackageConfig["retention"],
  coolingOffThreshold: string | null = null,
): T[] {
  const { versions_per_group: versionsPerGroup, groups_to_keep: groupsToKeep } = retention;

  const byGroup = new Map<string, T[]>();
  for (const v of versions) {
    if (!byGroup.has(v.versionGroup)) byGroup.set(v.versionGroup, []);
    byGroup.get(v.versionGroup)!.push(v);
  }

  // Sort groups newest-first via max version_sort (mirrors the DB query fix in listVersionGroups)
  const sortedGroups = [...byGroup.keys()].sort((a, b) => {
    const maxA = byGroup
      .get(a)!
      .map((v) => generateSortKey(v.version))
      .sort()
      .at(-1)!;
    const maxB = byGroup
      .get(b)!
      .map((v) => generateSortKey(v.version))
      .sort()
      .at(-1)!;
    return maxB.localeCompare(maxA);
  });

  const keptGroups =
    groupsToKeep !== undefined ? sortedGroups.slice(0, groupsToKeep) : sortedGroups;

  const result: T[] = [];
  for (const group of keptGroups) {
    const sorted = [...byGroup.get(group)!].sort((a, b) =>
      generateSortKey(b.version).localeCompare(generateSortKey(a.version)),
    );
    let servable = 0;
    for (const v of sorted) {
      if (computeCoolingOffUntil(v, retention, coolingOffThreshold) !== null) {
        result.push(v);
      } else if (servable < versionsPerGroup) {
        result.push(v);
        servable += 1;
      }
    }
  }
  return result;
}
