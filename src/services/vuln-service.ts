/**
 * Cross-reference CVE affects ranges against a package's cached versions
 * (plan §4, WAL-13). The core evaluation is a pure function over injected rows so
 * it is unit-testable without a DB; the route is a thin wrapper.
 */
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { evaluateRange, VERSION_NA, VersionRange } from "../vuln/version-ranges.js";
import {
  deriveCveVersion,
  describeNormalisation,
  patternFromAffects,
} from "../vuln/cve-version.js";

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
  suppression: {
    id: number;
    reason: string;
    created_by: string;
    package_name: string | null;
    expires_at: string | null;
  } | null;
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

export { VERSION_NA };

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
  // ADR-008: the package's normalisation rule travels on the rows it governs.
  const pattern = patternFromAffects(affects);
  return versions.map((v) => {
    const cveVersion = deriveCveVersion(v.version, pattern);
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
      const result = evaluateRange(cveVersion.value, toRange(row));
      if (result.matched)
        byCve.set(row.cve_id, {
          matched: row,
          reason: describeNormalisation(result.reason, cveVersion),
        });
    }

    const vulns: VersionVuln[] = [...byCve.entries()].map(([cveId, { matched, reason }]) => ({
      cve_id: cveId,
      severity: matched.severity,
      fixed_in: matched.fixed_in,
      is_kev: matched.is_kev,
      matched_because: reason,
      suppression: suppressionDetails(matched),
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

/** A concrete critical match: the CVE row that gates the version, and why its range matched. */
export interface BlockingCveMatch {
  cve: AffectsWithCveRow;
  /**
   * The range comparison in the form `evaluateRange` states it (`0.10.10 == 0.10.10`,
   * `2.55.0 < 2.56.0`, `all-versions`), annotated with the normalised version when ADR-008
   * normalisation changed what was compared. Same vocabulary as `matched_because` on
   * /packages/{name}/vulns, deliberately — it is the same fact.
   */
  matched_because: string;
}

/**
 * Classify whether a version may be served/recommended under the critical-CVE
 * gate shared by the groups and versions endpoints.
 */
export function getVersionAvailabilityStatus(
  version: string,
  affects: AffectsWithCveRow[],
): VersionAvailabilityStatus {
  return findBlockingCveMatch(version, affects) === null ? "available" : "blocked";
}

/**
 * The CVE row responsible for blocking this version and why its range matched, or null when
 * the version is servable.
 *
 * Availability history needs to record *why* a version became blocked, not just that it did, and
 * so does the download gate's 403 (WAL-79) — a developer whose build just failed has no thread to
 * pull from "blocked". Deriving that from a boolean predicate would mean re-running the match a
 * second time and risking the two drifting, so the predicate is expressed once here and both
 * `findBlockingCve` and `getVersionAvailabilityStatus` are defined in terms of it.
 *
 * Where several critical CVEs match, the worst one wins and the rest stay visible via
 * /packages/{name}/vulns. "Worst" is defined by `isWorseBlock` below rather than by input order:
 * the answer to "why is this blocked?" is now quoted back to a caller in an error body, and one
 * that changed between two identical requests because the affects rows arrived in a different
 * order would look like walrus contradicting itself.
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
export function findBlockingCveMatch(
  version: string,
  affects: AffectsWithCveRow[],
): BlockingCveMatch | null {
  // ADR-008: evaluate against the upstream version the served one embeds, where the package
  // declares how. Absent a rule this is the served version and nothing changes.
  const cveVersion = deriveCveVersion(version, patternFromAffects(affects));
  let worst: BlockingCveMatch | null = null;
  for (const row of affects) {
    if (!isKnownCritical(row)) continue;
    if (row.suppressed) continue;
    if (row.version_na) continue;
    const result = evaluateRange(cveVersion.value, toRange(row));
    if (!result.matched || result.reason === "range-uncomparable") continue;
    // ADR-008 part 3: a block caused by normalisation has to say so, or a `2.55.0.5` refused by
    // a range reading `2.55.0` reads as a defect rather than as the policy it is.
    const candidate: BlockingCveMatch = {
      cve: row,
      matched_because: describeNormalisation(result.reason, cveVersion),
    };
    if (worst === null || isWorseBlock(candidate, worst)) worst = candidate;
  }
  return worst;
}

/**
 * The CVE row responsible for blocking this version, or null when it is servable.
 *
 * The row-only view of `findBlockingCveMatch`, for the callers that store or count the CVE and
 * have nowhere to put the reason.
 */
export function findBlockingCve(
  version: string,
  affects: AffectsWithCveRow[],
): AffectsWithCveRow | null {
  return findBlockingCveMatch(version, affects)?.cve ?? null;
}

/**
 * Total order over two matching critical CVEs, so "the blocking CVE" is a property of the data
 * and not of the order it was loaded in.
 *
 * Severity first — of two true reasons to refuse a download, the higher-scoring one is the one
 * worth naming. The score compared is the max across v3/v4/v2, because that is the quantity the
 * gate itself thresholds (ADR-005, any-of): ranking on v3 alone would have a v4-only 9.9 lose to
 * a v3 9.0. KEV breaks a score tie — it does not gate on its own (PO, 2026-08-26) but
 * exploited-in-the-wild is the more urgent of two equally-scored advisories to put in front of
 * someone. `cve_id` and then the matched range settle the rest: arbitrary, but fixed, and two
 * rows of the same CVE can differ in `fixed_in`, which the caller is told to act on.
 */
function isWorseBlock(candidate: BlockingCveMatch, incumbent: BlockingCveMatch): boolean {
  const byScore = maxCvssScore(candidate.cve) - maxCvssScore(incumbent.cve);
  if (byScore !== 0) return byScore > 0;
  if (candidate.cve.is_kev !== incumbent.cve.is_kev) return candidate.cve.is_kev;
  return tieBreakKey(candidate) < tieBreakKey(incumbent);
}

/** The score the gate actually thresholds: the highest of v3/v4/v2, or -1 when none is scored. */
function maxCvssScore(row: AffectsWithCveRow): number {
  let max = -1;
  for (const score of [row.cvss_v3_score, row.cvss_v4_score, row.cvss_v2_score]) {
    if (score === null || score === undefined) continue;
    const value = Number(score);
    if (!Number.isNaN(value) && value > max) max = value;
  }
  return max;
}

function tieBreakKey(match: BlockingCveMatch): string {
  const row = match.cve;
  return [row.cve_id, match.matched_because, row.fixed_in ?? "", row.source].join("\u0000");
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

function suppressionDetails(row: AffectsWithCveRow): VersionVuln["suppression"] {
  if (!row.suppressed || row.suppression_id == null || !row.suppression_reason) return null;
  return {
    id: row.suppression_id,
    reason: row.suppression_reason,
    created_by: row.suppression_created_by ?? "unknown",
    package_name: row.suppression_package_name ?? null,
    expires_at: row.suppression_expires_at?.toISOString() ?? null,
  };
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
