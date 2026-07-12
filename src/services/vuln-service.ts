/**
 * Cross-reference CVE affects ranges against a package's cached versions
 * (plan §4, WAL-13). The core evaluation is a pure function over injected rows so
 * it is unit-testable without a DB; the route is a thin wrapper.
 */
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { evaluateRange, VersionRange } from "../vuln/version-ranges.js";

export interface CachedVersionInput {
  version: string;
  version_group: string;
}

export interface VersionVuln {
  cve_id: string;
  severity: string | null;
  fixed_in: string | null;
  is_kev: boolean;
  matched_because: string | null;
}

export interface VersionCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  kev: number;
}

export interface VersionVulnResult {
  version: string;
  version_group: string;
  counts: VersionCounts;
  vulns: VersionVuln[];
}

function toRange(row: AffectsWithCveRow): VersionRange {
  return {
    versionStart: row.version_start,
    versionStartExcl: row.version_start_excl,
    versionEnd: row.version_end,
    versionEndExcl: row.version_end_excl,
    exactVersion: row.exact_version,
  };
}

/**
 * For each cached version, evaluate every affects row and keep the CVEs whose
 * range matches (a CVE matches when ANY of its ranges match). Fails open:
 * uncomparable cached versions flag matches as `range-uncomparable` rather than
 * dropping them (consistent with the /vulns endpoint).
 */
export function crossReferenceVersions(
  versions: CachedVersionInput[],
  affects: AffectsWithCveRow[],
): VersionVulnResult[] {
  return versions.map((v) => {
    const byCve = new Map<string, { matched: AffectsWithCveRow; reason: string }>();
    for (const row of affects) {
      const existing = byCve.get(row.cve_id);
      // Prefer a concrete match over a fail-open one already recorded.
      if (existing && existing.reason !== "range-uncomparable") continue;
      const result = evaluateRange(v.version, toRange(row));
      if (result.matched) byCve.set(row.cve_id, { matched: row, reason: result.reason });
    }

    const vulns: VersionVuln[] = [...byCve.entries()].map(([cveId, { matched, reason }]) => ({
      cve_id: cveId,
      severity: matched.severity,
      fixed_in: matched.fixed_in,
      is_kev: matched.is_kev,
      matched_because: reason,
    }));

    return {
      version: v.version,
      version_group: v.version_group,
      counts: countBySeverity(vulns),
      vulns,
    };
  });
}

export interface GroupVersionInput {
  version: string;
  version_group: string;
  is_lts: boolean;
}

export interface VersionGroupSummary {
  group: string;
  is_lts: boolean;
  latest_available: string | null;
}

export type VersionAvailabilityStatus = "available" | "blocked";

/**
 * Classify whether a version may be served/recommended under the critical-CVE
 * gate shared by the groups and versions endpoints.
 */
export function getVersionAvailabilityStatus(
  version: string,
  affects: AffectsWithCveRow[],
): VersionAvailabilityStatus {
  return hasConcreteCriticalMatch(version, affects.filter(isKnownCritical))
    ? "blocked"
    : "available";
}

/**
 * Per-group summaries with the critical-CVE gate (WAL-29): latest_available is
 * the newest version in the group with no concrete match against a
 * known-critical CVE — cvss_v3_score >= 9.0, or severity CRITICAL when NVD
 * ships no score. Fail-open matches (range-uncomparable) do NOT gate: they are
 * uncertainty, not knowledge, and one unparseable range must not null out a
 * whole package; they stay visible via /packages/:name/vulns. When every
 * version in a group is critical-affected, latest_available is null — never a
 * vulnerable fallback (PO directive 2026-07-12).
 *
 * `versions` must be ordered newest first; group order follows first
 * appearance, i.e. groups sorted by their max version_sort.
 */
export function summarizeGroupsWithVulnGate(
  versions: GroupVersionInput[],
  affects: AffectsWithCveRow[],
): VersionGroupSummary[] {
  const critical = affects.filter(isKnownCritical);
  const groups = new Map<string, { is_lts: boolean; latest_available: string | null }>();
  for (const v of versions) {
    let group = groups.get(v.version_group);
    if (!group) {
      group = { is_lts: false, latest_available: null };
      groups.set(v.version_group, group);
    }
    group.is_lts ||= v.is_lts;
    if (group.latest_available === null && !hasConcreteCriticalMatch(v.version, critical)) {
      group.latest_available = v.version;
    }
  }
  return [...groups.entries()].map(([group, summary]) => ({ group, ...summary }));
}

function isKnownCritical(row: AffectsWithCveRow): boolean {
  if (row.cvss_v3_score !== null) return Number(row.cvss_v3_score) >= 9.0;
  return row.severity === "CRITICAL";
}

function hasConcreteCriticalMatch(version: string, criticalRows: AffectsWithCveRow[]): boolean {
  return criticalRows.some((row) => {
    const result = evaluateRange(version, toRange(row));
    return result.matched && result.reason !== "range-uncomparable";
  });
}

function countBySeverity(vulns: VersionVuln[]): VersionCounts {
  return {
    total: vulns.length,
    critical: vulns.filter((v) => v.severity === "CRITICAL").length,
    high: vulns.filter((v) => v.severity === "HIGH").length,
    medium: vulns.filter((v) => v.severity === "MEDIUM").length,
    low: vulns.filter((v) => v.severity === "LOW").length,
    kev: vulns.filter((v) => v.is_kev).length,
  };
}
