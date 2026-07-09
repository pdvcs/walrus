/**
 * Version comparison + range evaluation (ported from vulncheck `matching/versions.ts`).
 * Try semver first; fall back to a segment-by-segment comparator for non-semver
 * strings (`2021.1`, `1.0b`, `21.07`, `8.3.2.0`). Never throws: unparseable
 * comparisons return null ("uncomparable") so callers can fail open with a warning.
 *
 * Deliberately separate from `src/common/version-utils.ts` (`version_sort` is a
 * sort-key generator; range evaluation is a different contract). See plan §3 —
 * do not merge in v1.
 */
import semver from "semver";

export type Cmp = -1 | 0 | 1;

/** Compare two version strings. Returns null when uncomparable. */
export function compareVersions(a: string, b: string): Cmp | null {
  const na = normalizeVersion(a);
  const nb = normalizeVersion(b);
  if (na === null || nb === null) return null;

  const sa = semver.valid(semver.coerce(na, { loose: true }));
  const sb = semver.valid(semver.coerce(nb, { loose: true }));
  // semver.coerce drops segments beyond the third (8.3.2.0 → 8.3.2), so only
  // trust it when neither side has more than three numeric segments.
  if (
    sa &&
    sb &&
    !hasExtraSegments(na) &&
    !hasExtraSegments(nb) &&
    !hasAlphaSegment(na) &&
    !hasAlphaSegment(nb)
  ) {
    return semver.compare(sa, sb) as Cmp;
  }
  return compareSegments(na, nb);
}

/** True when the string can participate in comparisons at all. */
export function isComparable(v: string): boolean {
  return normalizeVersion(v) !== null;
}

function normalizeVersion(v: string): string | null {
  const t = v.trim().toLowerCase().replace(/^v/, "");
  if (!t || !/\d/.test(t)) return null; // must contain at least one digit
  return t;
}

function hasExtraSegments(v: string): boolean {
  return v.split(/[.\-_]/).filter((s) => /^\d+$/.test(s)).length > 3;
}

function hasAlphaSegment(v: string): boolean {
  return /[a-z]/.test(v);
}

/**
 * Fallback comparator: split on [.\-_], compare numerically where both
 * segments are numeric, lexically otherwise. "1.0b" style trailing letters
 * split into their own segment ("1", "0", "b"); a version with an extra
 * alpha segment sorts AFTER its base ("1.0b" > "1.0"), while an extra
 * numeric segment equal to zero is insignificant ("8.3.2.0" == "8.3.2").
 */
function compareSegments(a: string, b: string): Cmp {
  const as = segments(a);
  const bs = segments(b);
  const len = Math.max(as.length, bs.length);

  for (let i = 0; i < len; i++) {
    const x = as[i];
    const y = bs[i];
    if (x === undefined && y === undefined) return 0;
    if (x === undefined) return isInsignificant(bs.slice(i)) ? 0 : -1;
    if (y === undefined) return isInsignificant(as.slice(i)) ? 0 : 1;

    const xNum = /^\d+$/.test(x);
    const yNum = /^\d+$/.test(y);
    if (xNum && yNum) {
      const diff = Number(x) - Number(y);
      if (diff !== 0) return diff < 0 ? -1 : 1;
    } else if (xNum !== yNum) {
      // numeric vs alpha at same position: numeric (a real release segment)
      // sorts after pure-alpha (pre-release-ish) — "1.0.1" > "1.0.rc1" — but
      // a trailing alpha on otherwise-equal versions sorts after ("1.0b" > "1.0")
      // which is handled by the undefined branch above.
      return xNum ? 1 : -1;
    } else {
      const cmp = x.localeCompare(y);
      if (cmp !== 0) return cmp < 0 ? -1 : 1;
    }
  }
  return 0;
}

function segments(v: string): string[] {
  return v
    .split(/[.\-_]/)
    .flatMap((s) => s.match(/\d+|[a-z]+/g) ?? [])
    .filter(Boolean);
}

/** Trailing segments that don't change ordering: all-zero numerics. */
function isInsignificant(rest: string[]): boolean {
  return rest.every((s) => /^0+$/.test(s));
}

export interface VersionRange {
  versionStart: string | null;
  versionStartExcl: boolean;
  versionEnd: string | null;
  versionEndExcl: boolean;
  exactVersion: string | null;
}

export type RangeResult =
  | { matched: boolean; reason: string }
  | { matched: true; reason: "range-uncomparable" };

/**
 * Evaluate a version against an affects range. Fails OPEN: if any needed
 * comparison is impossible, the CVE is treated as matched with
 * reason 'range-uncomparable' (plan §3 — flag, never silently drop).
 */
export function evaluateRange(version: string, range: VersionRange): RangeResult {
  if (range.exactVersion !== null && range.exactVersion !== undefined) {
    const cmp = compareVersions(version, range.exactVersion);
    if (cmp === null) return { matched: true, reason: "range-uncomparable" };
    return cmp === 0
      ? { matched: true, reason: `${version} == ${range.exactVersion}` }
      : { matched: false, reason: `${version} != ${range.exactVersion}` };
  }

  const clauses: string[] = [];

  if (range.versionStart) {
    const cmp = compareVersions(version, range.versionStart);
    if (cmp === null) return { matched: true, reason: "range-uncomparable" };
    const ok = range.versionStartExcl ? cmp > 0 : cmp >= 0;
    if (!ok)
      return {
        matched: false,
        reason: `${version} ${range.versionStartExcl ? "<=" : "<"} ${range.versionStart}`,
      };
    clauses.push(`${version} ${range.versionStartExcl ? ">" : ">="} ${range.versionStart}`);
  }

  if (range.versionEnd) {
    const cmp = compareVersions(version, range.versionEnd);
    if (cmp === null) return { matched: true, reason: "range-uncomparable" };
    const ok = range.versionEndExcl ? cmp < 0 : cmp <= 0;
    if (!ok)
      return {
        matched: false,
        reason: `${version} ${range.versionEndExcl ? ">=" : ">"} ${range.versionEnd}`,
      };
    clauses.push(`${version} ${range.versionEndExcl ? "<" : "<="} ${range.versionEnd}`);
  }

  if (clauses.length === 0) {
    // No version info at all on the range: the CPE says "all versions".
    return { matched: true, reason: "all-versions" };
  }
  return { matched: true, reason: clauses.join(" and ") };
}

/** Human-readable range description for API responses ("< 8.5.6", ">= 1.0, <= 2.0"). */
export function describeRange(range: VersionRange): string {
  if (range.exactVersion) return `== ${range.exactVersion}`;
  const parts: string[] = [];
  if (range.versionStart)
    parts.push(`${range.versionStartExcl ? ">" : ">="} ${range.versionStart}`);
  if (range.versionEnd) parts.push(`${range.versionEndExcl ? "<" : "<="} ${range.versionEnd}`);
  return parts.length ? parts.join(", ") : "all versions";
}
