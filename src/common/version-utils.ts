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
 * Sort-key alphabet. Keys are compared byte-wise, both in JS (`<`) and in SQL
 * (`ORDER BY version_sort`), so the relative ASCII order of these three is the
 * whole ordering contract:
 *
 *   PRERELEASE_MARK (45)  <  digits (48-57)  <  COMPONENT_MARK (126)
 *
 * `1.2.3-rc1`  -> "000001.000002.000003-rc1"        below the release
 * `1.2.3`      -> "000001.000002.000003~"           the release
 * `1.2.3.4`    -> "000001.000002.000003~000004~"    a strict extension of it
 *
 * A stable key is terminated by COMPONENT_MARK, and every component past the
 * third is introduced by that same mark. A longer version's key therefore has
 * the shorter version's key as a strict prefix and sorts above it — which is
 * exactly what a four-component build is: a continuation of the three-component
 * one, not a sibling of it. (WAL-63: the old scheme terminated with `~` but
 * separated overflow components with `.` (46), so `2025.3.6` outranked its own
 * `2025.3.6.1`.)
 */
const COMPONENT_MARK = "~";
const PRERELEASE_MARK = "-";
const SEGMENT_WIDTH = 6;
const BASE_SEGMENTS = 3;

function padSegment(segment: string): string {
  return segment.padStart(SEGMENT_WIDTH, "0");
}

/** Pad numeric pre-release identifiers so `rc.9` sorts below `rc.10`; leave the rest verbatim. */
function renderPrerelease(identifiers: readonly (string | number)[]): string {
  return identifiers
    .map((id) => {
      const s = String(id);
      return /^\d+$/.test(s) ? padSegment(s) : s;
    })
    .join(".");
}

/**
 * Generate a zero-padded sort key for lexicographic version ordering.
 * Handles:
 *  - Standard semver: 1.2.3 → "000001.000002.000003~"
 *  - Build metadata: 21.0.3+9 → normalized semver "21.0.3" → "000021.000000.000003~"
 *  - CalVer: 2024.01.15 → "002024.000001.000015~"
 *  - Short versions: 2026.2 → "002026.000002.000000~" (read as 2026.2.0, as semver reads it)
 *  - Four-plus components: 2025.3.6.1 → "002025.000003.000006~000001~"
 *  - Pre-release: 1.0.0-alpha.1 → lower sort key than 1.0.0
 *
 * Strategy: parse numeric segments and pad each to 6 digits. Keys are plain
 * strings compared byte-wise — see the alphabet note above — because
 * `versions.version_sort` is a stored column ordered by SQL, not by a JS
 * comparator.
 */
export function generateSortKey(version: string): string {
  // Strip build metadata suffix for sort purposes (but keep pre-release)
  const withoutBuild = version.replace(/\+.*$/, "");
  const trimmed = withoutBuild.replace(/^[v=\s]*/, "");
  const match = /^(\d+(?:\.\d+)*)(.*)$/.exec(trimmed);
  const components = match ? match[1].split(".") : [];
  const trailing = match ? match[2] : trimmed;

  // Only hand semver versions of the shape it actually models. Its loose parser reads a fourth
  // component as an undelimited pre-release whenever the patch has more than one digit —
  // `0.0.10.0` comes back as `0.0.1-0.0` — which would key a build below the version it
  // extends. Three components or fewer is the branch every shipped package takes, and its
  // output is byte-identical to the pre-WAL-63 implementation.
  if (components.length <= 3) {
    const parsed = semver.parse(withoutBuild, { loose: true });
    if (parsed) {
      const base = [parsed.major, parsed.minor, parsed.patch]
        .map((n) => padSegment(String(n)))
        .join(".");
      if (parsed.prerelease.length > 0) {
        return `${base}${PRERELEASE_MARK}${renderPrerelease(parsed.prerelease)}`;
      }
      return `${base}${COMPONENT_MARK}`;
    }
  }

  // Everything else: CalVer, four-component builds, anything semver declines. Take the leading
  // run of dotted numbers as components and treat whatever trails as a pre-release suffix, so
  // these keys interleave with the semver ones above.
  const base = Array.from({ length: BASE_SEGMENTS }, (_, i) =>
    padSegment(components[i] ?? "0"),
  ).join(".");
  const overflow = components
    .slice(BASE_SEGMENTS)
    .map((c) => `${COMPONENT_MARK}${padSegment(c)}`)
    .join("");

  if (trailing === "") return `${base}${overflow}${COMPONENT_MARK}`;
  const suffix = trailing.replace(/^[-.]/, "");
  return `${base}${overflow}${PRERELEASE_MARK}${renderPrerelease(suffix.split("."))}`;
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
