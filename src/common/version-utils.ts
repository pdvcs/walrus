import semver from "semver";

/**
 * Extract a version group (retention/API bucket) using a regex.
 * The regex must have one capture group.
 * e.g. "21.0.3+9" with "^(\\d+)" → "21"
 *      "1.24.1"   with "^(\\d+\\.\\d+)" → "1.24"
 */
export function extractVersionGroup(version: string, regex: string): string | null {
  const match = version.match(new RegExp(regex));
  if (!match || match[1] === undefined) return null;
  return match[1];
}

/**
 * Strip a tag prefix using a regex (one capture group).
 * e.g. "go1.24.1" with "^go(\\d+.*)" → "1.24.1"
 * Returns the original string if no match.
 */
export function applyTagPattern(tag: string, pattern: string): string | null {
  const match = tag.match(new RegExp(pattern));
  if (!match || match[1] === undefined) return null;
  return match[1];
}

/**
 * Generate a zero-padded sort key for lexicographic version ordering.
 * Handles:
 *  - Standard semver: 1.2.3 → "0001.0002.0003"
 *  - Build metadata: 21.0.3+9 → normalized semver "21.0.3+9" → "0021.0000.0003"
 *  - CalVer: 2024.01.15 → "2024.0001.0015"
 *  - Pre-release: 1.0.0-alpha.1 → lower sort key than 1.0.0
 *
 * Strategy: parse numeric segments and pad each to 6 digits.
 */
export function generateSortKey(version: string): string {
  // Strip build metadata suffix for sort purposes (but keep pre-release)
  const withoutBuild = version.replace(/\+.*$/, "");

  // Try semver parse (handles pre-release correctly)
  const parsed = semver.parse(withoutBuild, { loose: true });
  if (parsed) {
    const base = `${String(parsed.major).padStart(6, "0")}.${String(parsed.minor).padStart(6, "0")}.${String(parsed.patch).padStart(6, "0")}`;
    if (parsed.prerelease.length > 0) {
      // Pre-release sorts below stable — use '-' which is ASCII 45, below '~' (126)
      const pre = parsed.prerelease
        .map((p) => (typeof p === "number" ? String(p).padStart(6, "0") : p))
        .join(".");
      return `${base}-${pre}`;
    }
    // Stable release — append '~' (ASCII 126) so it sorts above any pre-release suffix
    return `${base}~`;
  }

  // Fallback: split on dots and pad numeric segments
  const parts = withoutBuild.split(".");
  return parts.map((p) => (/^\d+$/.test(p) ? p.padStart(6, "0") : p)).join(".");
}

/**
 * Compare two version strings. Returns negative if a < b, positive if a > b, 0 if equal.
 * Uses sort keys for comparison.
 */
export function compareVersions(a: string, b: string): number {
  const keyA = generateSortKey(a);
  const keyB = generateSortKey(b);
  if (keyA < keyB) return -1;
  if (keyA > keyB) return 1;
  return 0;
}

/**
 * Sort versions in descending order (newest first).
 */
export function sortVersionsDesc(versions: string[]): string[] {
  return [...versions].sort((a, b) => compareVersions(b, a));
}

/**
 * Parse version — normalize by stripping 'v' prefix if present.
 */
export function parseVersion(version: string): string {
  return version.startsWith("v") ? version.slice(1) : version;
}
