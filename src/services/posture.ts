import { compareVersions } from "../common/version-utils.js";
import type { PackageRow } from "../types/db.js";
import { VERSION_NA } from "../vuln/version-ranges.js";
import { VULN_DISCLAIMER } from "../routes/schemas.js";
import {
  queryVulns,
  type DataFreshness,
  type VulnCounts,
  type VulnItem,
  type VulnQueryDeps,
} from "./vuln-query.js";

/**
 * Vulnerability posture of one package at one version (WAL-54).
 *
 * `clean` is a positive claim, so it is only made when it can be defended:
 *   - the package is tracked at all,
 *   - every configured source (NVD via CPE pairs, OSV via the ecosystem mapping) has been read
 *     for it — an empty result before that is "not looked yet", not "nothing there",
 *   - the version parses, and no advisory was left unevaluated (range could not be compared).
 * Anything short of that is `unknown`, with the reasons spelled out. `vulnerable` needs at least
 * one advisory whose range was actually evaluated against the version.
 */
export type PostureStatus = "clean" | "vulnerable" | "unknown";

export type UnknownReason =
  | "no-version"
  | "version-unparseable"
  | "not-tracked"
  | "coverage-incomplete"
  | "inconclusive-ranges";

export type SourceCoverage = "complete" | "pending" | "not-configured";

export interface PostureVuln extends VulnItem {
  /** False when the advisory is listed but its range could not be evaluated for this version. */
  confirmed: boolean;
}

export interface PostureResult {
  package: string;
  display_name: string;
  /** The version assessed; null only when none was given and none is known. */
  version: string | null;
  version_source: "requested" | "latest" | null;
  latest_version: string | null;
  latest_version_checked_at: string | null;
  latest_version_error: string | null;
  /** Whether `version` is the known latest; null when either is unknown. */
  is_latest: boolean | null;
  status: PostureStatus;
  unknown_reasons: UnknownReason[];
  coverage: { nvd: SourceCoverage; osv: SourceCoverage };
  counts: VulnCounts;
  /** Confirmed advisories with no known fixed version. */
  unfixed: number;
  /**
   * Lowest version expected to clear every confirmed advisory, taken from the advisories' own
   * `fixed_in`. Null when there is nothing to fix, or when any confirmed advisory has no known fix.
   */
  upgrade_to: string | null;
  vulns: PostureVuln[];
  data_freshness: DataFreshness;
  disclaimer: string;
}

export interface PostureDeps {
  query: VulnQueryDeps;
  getPackage: (name: string) => Promise<PackageRow | null>;
  countCpes: (name: string) => Promise<number>;
  /** Newest cached version of a served package, for when the caller names none. */
  newestCachedVersion: (name: string) => Promise<string | null>;
}

/** Listed, but not evaluated against the version — never counted toward a verdict. */
function isUnconfirmed(matchedBecause: string | null): boolean {
  return (
    matchedBecause !== null &&
    (matchedBecause.startsWith("range-uncomparable") || matchedBecause === VERSION_NA)
  );
}

function coverage(configured: boolean, done: boolean): SourceCoverage {
  return !configured ? "not-configured" : done ? "complete" : "pending";
}

/** Null when the package row does not exist. */
export async function getPosture(
  deps: PostureDeps,
  name: string,
  requestedVersion?: string,
): Promise<PostureResult | null> {
  const pkg = await deps.getPackage(name);
  if (!pkg) return null;

  const requested = requestedVersion?.trim() || undefined;
  let version: string | null = requested ?? null;
  let versionSource: PostureResult["version_source"] = requested ? "requested" : null;
  if (!version) {
    // A watch package's latest comes from its [latest] lookup; a served one's from its cache.
    version = pkg.watch_only ? pkg.latest_version : await deps.newestCachedVersion(name);
    if (version) versionSource = "latest";
  }
  const latest = pkg.watch_only ? pkg.latest_version : await deps.newestCachedVersion(name);

  const cpeCount = await deps.countCpes(name);
  const hasOsv = pkg.osv_ecosystem !== null && pkg.osv_name !== null;
  const cov = {
    nvd: coverage(cpeCount > 0, pkg.vuln_backfill_completed_at !== null),
    osv: coverage(hasOsv, pkg.osv_synced_at !== null),
  };

  const reasons: UnknownReason[] = [];
  if (cpeCount === 0 && !hasOsv) reasons.push("not-tracked");
  if (!version) reasons.push("no-version");
  if (cov.nvd === "pending" || cov.osv === "pending") reasons.push("coverage-incomplete");

  // Without a version every advisory would "match" (reason no-version-given), which is the
  // opposite of a posture — so no query at all; the verdict is unknown, not vulnerable.
  let items: VulnItem[] = [];
  let freshness: DataFreshness;
  let disclaimer: string;
  if (version) {
    const result = await queryVulns(deps.query, { product: name, version });
    // The resolver can fuzzy-match; posture is about exactly this package or nothing.
    if (result.match.resolved && result.match.product_slug === name) items = result.vulns;
    if (result.version_parse_warning) reasons.push("version-unparseable");
    freshness = result.data_freshness;
    disclaimer = result.disclaimer;
  } else {
    freshness = await deps.query.getDataFreshness();
    disclaimer = VULN_DISCLAIMER;
  }

  const vulns: PostureVuln[] = items.map((v) => ({
    ...v,
    confirmed: !isUnconfirmed(v.affected.matched_because),
  }));
  const confirmed = vulns.filter((v) => v.confirmed);
  if (version && vulns.length > confirmed.length && !reasons.includes("version-unparseable")) {
    reasons.push("inconclusive-ranges");
  }

  let status: PostureStatus;
  if (confirmed.length > 0) {
    // A real match stands whatever else is missing: more data can only add to it.
    status = "vulnerable";
  } else if (reasons.length > 0) {
    status = "unknown";
  } else {
    status = "clean";
  }

  // Counts describe what the verdict rests on. Unconfirmed advisories stay in `vulns`, flagged,
  // but a version we could not evaluate must not inflate the severity tallies.
  const counts: VulnCounts = {
    total: confirmed.length,
    critical: confirmed.filter((v) => v.severity === "CRITICAL").length,
    high: confirmed.filter((v) => v.severity === "HIGH").length,
    medium: confirmed.filter((v) => v.severity === "MEDIUM").length,
    low: confirmed.filter((v) => v.severity === "LOW").length,
    unrated: confirmed.filter(
      (v) => !["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(v.severity ?? ""),
    ).length,
    kev: confirmed.filter((v) => v.is_kev).length,
  };

  const unfixed = confirmed.filter((v) => v.fixed_in === null).length;
  const fixes = confirmed.map((v) => v.fixed_in).filter((f): f is string => f !== null);
  const upgradeTo =
    confirmed.length > 0 && unfixed === 0
      ? fixes.reduce((hi, f) => (compareVersions(f, hi) > 0 ? f : hi))
      : null;

  return {
    package: name,
    display_name: pkg.display_name,
    version,
    version_source: versionSource,
    latest_version: latest,
    latest_version_checked_at: pkg.latest_version_checked_at?.toISOString() ?? null,
    latest_version_error: pkg.latest_version_error,
    is_latest: version && latest ? compareVersions(version, latest) === 0 : null,
    status,
    unknown_reasons: [...new Set(reasons)],
    coverage: cov,
    counts,
    unfixed,
    upgrade_to: upgradeTo,
    vulns: sortBySeverity(vulns),
    data_freshness: freshness,
    disclaimer,
  };
}

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

/** Confirmed before unconfirmed, then worst first, KEV ahead of non-KEV within a band. */
function sortBySeverity(vulns: PostureVuln[]): PostureVuln[] {
  return [...vulns].sort(
    (a, b) =>
      Number(b.confirmed) - Number(a.confirmed) ||
      (SEVERITY_RANK[a.severity ?? ""] ?? 4) - (SEVERITY_RANK[b.severity ?? ""] ?? 4) ||
      Number(b.is_kev) - Number(a.is_kev) ||
      a.cve_id.localeCompare(b.cve_id),
  );
}
