/**
 * Shared /vulns query core (plan §4). Extracted so the public API route
 * (GET /api/v1/vulns) and the admin explorer render from the exact same code
 * path — no duplicated resolution/matching logic.
 */
import { Resolution } from "../vuln/resolver.js";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { VULN_DISCLAIMER } from "../routes/schemas.js";
import {
  describeRange,
  evaluateRange,
  isComparable,
  VersionRange,
} from "../vuln/version-ranges.js";

export interface DataFreshness {
  nvd_last_sync: string | null;
  kev_last_sync: string | null;
  osv_last_sync: string | null;
}

export interface VulnQueryDeps {
  resolvePackage: (query: string) => Promise<Resolution>;
  listAffectsForPackage: (packageName: string) => Promise<AffectsWithCveRow[]>;
  getDataFreshness: () => Promise<DataFreshness>;
  logUnresolved: (query: string, top?: { slug: string; score: number }) => Promise<void>;
}

export interface VulnItem {
  cve_id: string;
  severity: string | null;
  cvss_v3_score: number | null;
  summary: string | null;
  affected: { range: string; matched_because: string | null };
  fixed_in: string | null;
  is_kev: boolean;
  sources: string[];
  references: string[];
}

export interface VulnCounts {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  kev: number;
}

export interface VulnQueryResult {
  query: { product: string; version: string | null };
  match: {
    resolved: boolean;
    product_slug: string | null;
    display_name: string | null;
    confidence: number | null;
    method: Resolution["method"];
    candidates: Resolution["candidates"];
  };
  vulns: VulnItem[];
  unmatched_vulns?: VulnItem[];
  counts: VulnCounts;
  version_parse_warning?: string;
  data_freshness: DataFreshness;
  disclaimer: string;
}

export async function queryVulns(
  deps: VulnQueryDeps,
  opts: { product: string; version?: string; includeUnmatched?: boolean },
): Promise<VulnQueryResult> {
  const { product, version, includeUnmatched = false } = opts;
  const match = await deps.resolvePackage(product);
  const freshness = await deps.getDataFreshness();

  const base = {
    query: { product, version: version ?? null },
    match: {
      resolved: match.resolved,
      product_slug: match.slug,
      display_name: match.displayName,
      confidence: match.confidence,
      method: match.method,
      candidates: match.candidates,
    },
    data_freshness: freshness,
    disclaimer: VULN_DISCLAIMER,
  };

  if (!match.resolved || !match.slug) {
    await deps.logUnresolved(product, match.candidates[0]);
    return { ...base, vulns: [], counts: emptyCounts() };
  }

  const rows = await deps.listAffectsForPackage(match.slug);
  const versionGiven = Boolean(version && version.trim());
  const versionParseWarning =
    versionGiven && !isComparable(version!)
      ? `version "${version}" could not be parsed; range checks are inconclusive and matching CVEs are included flagged as range-uncomparable`
      : undefined;

  const byCve = new Map<
    string,
    { rows: AffectsWithCveRow[]; matchedRow: AffectsWithCveRow | null; reason: string | null }
  >();
  for (const row of rows) {
    let entry = byCve.get(row.cve_id);
    if (!entry) {
      entry = { rows: [], matchedRow: null, reason: null };
      byCve.set(row.cve_id, entry);
    }
    entry.rows.push(row);

    if (!versionGiven) {
      if (!entry.matchedRow) {
        entry.matchedRow = row;
        entry.reason = "no-version-given";
      }
      continue;
    }
    if (!entry.matchedRow || entry.reason === "range-uncomparable") {
      const result = evaluateRange(version!, toRange(row));
      if (result.matched) {
        entry.matchedRow = row;
        entry.reason = result.reason;
      }
    }
  }

  const vulns: VulnItem[] = [];
  const unmatched: VulnItem[] = [];
  for (const [cveId, entry] of byCve) {
    const sources = [...new Set(entry.rows.map((r) => r.source))].sort();
    const row = entry.matchedRow ?? entry.rows[0];
    const item: VulnItem = {
      cve_id: cveId,
      severity: row.severity,
      cvss_v3_score: row.cvss_v3_score !== null ? Number(row.cvss_v3_score) : null,
      summary: truncate(row.description, 300),
      affected: { range: describeRange(toRange(row)), matched_because: entry.reason },
      fixed_in: row.fixed_in,
      is_kev: row.is_kev,
      sources,
      references: buildReferences(cveId, row),
    };
    if (entry.matchedRow) vulns.push(item);
    else if (includeUnmatched)
      unmatched.push({ ...item, affected: { ...item.affected, matched_because: null } });
  }

  const counts: VulnCounts = {
    total: vulns.length,
    critical: vulns.filter((v) => v.severity === "CRITICAL").length,
    high: vulns.filter((v) => v.severity === "HIGH").length,
    medium: vulns.filter((v) => v.severity === "MEDIUM").length,
    low: vulns.filter((v) => v.severity === "LOW").length,
    kev: vulns.filter((v) => v.is_kev).length,
  };

  return {
    ...base,
    ...(versionParseWarning ? { version_parse_warning: versionParseWarning } : {}),
    vulns,
    ...(includeUnmatched ? { unmatched_vulns: unmatched } : {}),
    counts,
  };
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

function buildReferences(cveId: string, row: AffectsWithCveRow): string[] {
  const nvdLink = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const refs = (row.raw?.cve?.references ?? []).map((r) => r.url).slice(0, 5);
  return [nvdLink, ...refs.filter((u) => u !== nvdLink)];
}

function truncate(s: string | null, n: number): string | null {
  if (s === null) return null;
  return s.length <= n ? s : `${s.slice(0, n - 1)}…`;
}

function emptyCounts(): VulnCounts {
  return { total: 0, critical: 0, high: 0, medium: 0, low: 0, kev: 0 };
}
