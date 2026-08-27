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

/**
 * `matched_because` for a row whose CPE carried NA in its version component. Not a range
 * evaluation result — `evaluateRange` never sees these rows — so it is defined here beside the
 * only code that produces it.
 */
export const VERSION_NA = "version-not-applicable";

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
      // Prefer a concrete match over a weak one already recorded — a fail-open match, or a CPE
      // that names no version to match against.
      if (existing && existing.reason !== "range-uncomparable" && existing.reason !== VERSION_NA)
        continue;
      // NA rows are listed, never gated (see findBlockingCve). Reporting them under their own
      // reason is what keeps "walrus knows about this advisory" separable from "this advisory
      // applies to your version" — the Arduino extension CVE stays visible against vscode.
      if (row.version_na) {
        if (!existing) byCve.set(row.cve_id, { matched: row, reason: VERSION_NA });
        continue;
      }
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
  return findBlockingCve(version, affects) === null ? "available" : "blocked";
}

/**
 * The CVE row responsible for blocking this version, or null when it is servable.
 *
 * Availability history needs to record *why* a version became blocked, not just that it did.
 * Deriving that from a boolean predicate would mean re-running the match a second time and
 * risking the two drifting, so the predicate is expressed once here and
 * `getVersionAvailabilityStatus` is defined in terms of it.
 *
 * Where several critical CVEs match, the first concrete match wins — the answer to "why is
 * this blocked?" only needs to be *a* true reason, and the rest stay visible via
 * /packages/{name}/vulns.
 *
 * NA-versioned rows (`version_na`) never gate. A CPE carrying `-` in its version component
 * states that the version attribute does not apply to that entry, so it names nothing to
 * compare a served version against — CNAs file this way against products they cannot version,
 * and reading it as "all versions" blocked every VS Code build on an Arduino *extension*
 * advisory (WAL-69). This is the same "matched for display, excluded from gating" treatment
 * `range-uncomparable` already gets below, on stronger grounds: that one is uncertainty, this
 * one is a positive statement that no shipped version is enumerable. `*` with no bounds is
 * untouched and still gates — it genuinely does mean every version.
 */
export function findBlockingCve(
  version: string,
  affects: AffectsWithCveRow[],
): AffectsWithCveRow | null {
  for (const row of affects) {
    if (!isKnownCritical(row)) continue;
    if (row.version_na) continue;
    const result = evaluateRange(version, toRange(row));
    if (result.matched && result.reason !== "range-uncomparable") return row;
  }
  return null;
}

/**
 * Per-group summaries with the critical-CVE gate (WAL-29): latest_available is
 * the newest version in the group with no concrete match against a
 * known-critical CVE — any CVSS base score >= 9.0 (v3, v4, or v2), or severity
 * CRITICAL when NVD ships no score; see `meetsCriticalGate`.
 * Fail-open matches (range-uncomparable) do NOT gate: they are
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

/** The download-gate threshold. The single definition — do not restate 9.0 elsewhere. */
export const CRITICAL_SCORE = 9.0;

/**
 * The critical-CVE gate predicate, stated once for every consumer (download
 * route, group summaries, enrichment preview).
 *
 * A CVE is known-critical when ANY CVSS base score — v3, v4, or v2 — reaches
 * the threshold, or when it carries a score-less CRITICAL severity. Any-of
 * semantics is the PO-decided policy (2026-08-26, ADR-005): this deployment
 * errs on the side of denial, so a v2-only 10.0 or a v4-only 9.5 blocks even
 * though neither would have produced a v3 score. v2 has no CRITICAL band, so
 * without the score test v2-only criticals never blocked at all.
 *
 * KEV is deliberately absent: exploited-in-the-wild is signal (badges, counts,
 * history), not a blocker — PO decision 2026-08-26, may be revisited.
 *
 * Scores arrive as strings from pg NUMERIC columns and as numbers from
 * enrichment proposals; Number() covers both, and null/undefined (NaN) fails
 * the comparison safely.
 */
export function meetsCriticalGate(cve: {
  cvss_v3_score: number | string | null;
  cvss_v4_score?: number | string | null;
  cvss_v2_score?: number | string | null;
  severity: string | null;
}): boolean {
  for (const score of [cve.cvss_v3_score, cve.cvss_v4_score, cve.cvss_v2_score]) {
    if (score !== null && score !== undefined && Number(score) >= CRITICAL_SCORE) return true;
  }
  return cve.severity === "CRITICAL";
}

function isKnownCritical(row: AffectsWithCveRow): boolean {
  return meetsCriticalGate(row);
}

function hasConcreteCriticalMatch(version: string, criticalRows: AffectsWithCveRow[]): boolean {
  // criticalRows is pre-filtered by callers; findBlockingCve re-checks, which is harmless
  // and keeps the match rule in one place.
  return findBlockingCve(version, criticalRows) !== null;
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
