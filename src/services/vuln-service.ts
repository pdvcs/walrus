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
