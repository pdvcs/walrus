import { describe, it, expect } from "vitest";
import {
  crossReferenceVersions,
  findBlockingCve,
  findBlockingCveMatch,
  getVersionAvailabilityStatus,
  summarizeGroupsWithVulnGate,
  VERSION_NA,
} from "../../src/services/vuln-service.js";
import type { AffectsWithCveRow } from "../../src/db/queries/cves.js";

function affects(overrides: Partial<AffectsWithCveRow>): AffectsWithCveRow {
  return {
    cve_id: "CVE-2023-0001",
    version_start: null,
    version_start_excl: false,
    version_end: "8.5.6",
    version_end_excl: false,
    exact_version: null,
    fixed_in: null,
    source: "nvd",
    severity: "HIGH",
    severity_source: "nvd-cvss-v3",
    cvss_v3_score: "7.5",
    cvss_v4_score: null,
    cvss_v2_score: null,
    description: null,
    is_kev: false,
    raw: null,
    version_na: false,
    ...overrides,
  };
}

describe("crossReferenceVersions", () => {
  it("lists a CVE on an affected version and none on a fixed version", () => {
    const rows = [
      affects({ cve_id: "CVE-A", version_end: "20", version_end_excl: true, fixed_in: "20" }),
    ];
    const res = crossReferenceVersions(
      [
        { version: "11.0.2", version_group: "11" },
        { version: "21.0.1", version_group: "21" },
      ],
      rows,
    );
    const v11 = res.find((r) => r.version === "11.0.2")!;
    const v21 = res.find((r) => r.version === "21.0.1")!;
    expect(v11.counts.total).toBe(1);
    expect(v11.vulns[0].cve_id).toBe("CVE-A");
    expect(v11.vulns[0].fixed_in).toBe("20");
    expect(v21.counts.total).toBe(0);
  });

  it("a CVE matches when ANY of its ranges match (multi-range same cve)", () => {
    const rows = [
      affects({ cve_id: "CVE-M", version_end: "2.0", version_end_excl: true }),
      affects({
        cve_id: "CVE-M",
        version_start: "5.0",
        version_end: "6.0",
        version_end_excl: true,
      }),
    ];
    const res = crossReferenceVersions([{ version: "5.5", version_group: "5" }], rows);
    expect(res[0].counts.total).toBe(1); // collapsed to one CVE
  });

  it("counts by severity and KEV", () => {
    const rows = [
      affects({ cve_id: "C1", severity: "CRITICAL", is_kev: true }),
      affects({ cve_id: "C2", severity: "HIGH" }),
      affects({ cve_id: "C3", severity: "LOW" }),
    ];
    const res = crossReferenceVersions([{ version: "1.0", version_group: "1" }], rows);
    expect(res[0].counts).toMatchObject({ total: 3, critical: 1, high: 1, low: 1, kev: 1 });
  });

  it("fails open on an uncomparable cached version (flagged range-uncomparable)", () => {
    const rows = [affects({ cve_id: "C1", version_end: "8.5.6", version_end_excl: true })];
    const res = crossReferenceVersions([{ version: "not-a-version", version_group: "x" }], rows);
    expect(res[0].counts.total).toBe(1);
    expect(res[0].vulns[0].matched_because).toBe("range-uncomparable");
  });
});

describe("summarizeGroupsWithVulnGate", () => {
  const v = (version: string, version_group: string, is_lts = false) => ({
    version,
    version_group,
    is_lts,
  });

  it("returns the newest version per group when no affects rows exist (untracked)", () => {
    const res = summarizeGroupsWithVulnGate(
      [v("21.0.3", "21", true), v("21.0.2", "21", true), v("17.0.11", "17", true)],
      [],
    );
    expect(res).toEqual([
      { group: "21", is_lts: true, latest_available: "21.0.3" },
      { group: "17", is_lts: true, latest_available: "17.0.11" },
    ]);
  });

  it("skips past a critical-affected newest version to the next clean one", () => {
    const rows = [
      affects({
        cve_id: "CVE-CRIT",
        severity: "CRITICAL",
        cvss_v3_score: "9.8",
        exact_version: "21.0.3",
        version_end: null,
      }),
    ];
    const res = summarizeGroupsWithVulnGate([v("21.0.3", "21"), v("21.0.2", "21")], rows);
    expect(res[0].latest_available).toBe("21.0.2");
  });

  it("returns null when every version in the group is critical-affected", () => {
    const rows = [affects({ cve_id: "CVE-CRIT", cvss_v3_score: "9.1", version_end: "22" })];
    const res = summarizeGroupsWithVulnGate([v("21.0.3", "21"), v("21.0.2", "21")], rows);
    expect(res).toEqual([{ group: "21", is_lts: false, latest_available: null }]);
  });

  it("ignores non-critical CVEs (score < 9)", () => {
    const rows = [
      affects({ cve_id: "CVE-HIGH", severity: "HIGH", cvss_v3_score: "8.9", version_end: "22" }),
    ];
    const res = summarizeGroupsWithVulnGate([v("21.0.3", "21")], rows);
    expect(res[0].latest_available).toBe("21.0.3");
  });

  it("treats a score-less severity=CRITICAL CVE as known-critical", () => {
    const rows = [
      affects({
        cve_id: "CVE-NOSCORE",
        severity: "CRITICAL",
        cvss_v3_score: null,
        version_end: "22",
      }),
    ];
    const res = summarizeGroupsWithVulnGate([v("23.0.0", "23"), v("21.0.3", "21")], rows);
    expect(res).toEqual([
      { group: "23", is_lts: false, latest_available: "23.0.0" },
      { group: "21", is_lts: false, latest_available: null },
    ]);
  });

  it("does not gate on fail-open (range-uncomparable) matches", () => {
    const rows = [
      affects({
        cve_id: "CVE-CRIT",
        cvss_v3_score: "9.8",
        exact_version: "not-a-version",
        version_end: null,
      }),
    ];
    const res = summarizeGroupsWithVulnGate([v("21.0.3", "21")], rows);
    expect(res[0].latest_available).toBe("21.0.3");
  });

  it("gates on a concrete critical match even when the cached version is odd elsewhere", () => {
    // Same range shape the /vulns endpoint fails open on, but here the version IS comparable.
    const rows = [
      affects({
        cve_id: "CVE-CRIT",
        cvss_v3_score: "10.0",
        version_end: "9",
        version_end_excl: true,
      }),
    ];
    const res = summarizeGroupsWithVulnGate([v("8.5", "8")], rows);
    expect(res[0].latest_available).toBeNull();
  });

  it("preserves newest-first group ordering and bool_or LTS semantics", () => {
    const res = summarizeGroupsWithVulnGate(
      [v("21.0.3", "21", false), v("21.0.2", "21", true), v("17.0.11", "17", true)],
      [],
    );
    expect(res.map((g) => g.group)).toEqual(["21", "17"]);
    expect(res[0].is_lts).toBe(true);
  });
});

describe("getVersionAvailabilityStatus", () => {
  it("blocks a concrete CVSS >= 9 match", () => {
    const rows = [
      affects({
        cve_id: "CVE-CRIT",
        cvss_v3_score: "9.0",
        exact_version: "1.24.13",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("blocked");
    expect(getVersionAvailabilityStatus("1.24.12", rows)).toBe("available");
  });

  it("does not block a range-uncomparable match", () => {
    const rows = [
      affects({
        cve_id: "CVE-CRIT",
        cvss_v3_score: "9.8",
        exact_version: "not-a-version",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("available");
  });

  // PO decision 2026-08-26 (ADR-005): ANY CVSS base score >= 9.0 blocks, whichever
  // version produced it. v2 has no CRITICAL band, so before this a v2-only 10.0
  // never blocked; v4-only CVEs were invisible entirely.
  it("blocks on a v2-only score >= 9.0 despite a non-critical severity label", () => {
    const rows = [
      affects({
        cve_id: "CVE-V2-CRIT",
        severity: "HIGH", // the most v2 can say
        severity_source: "nvd-cvss-v2",
        cvss_v3_score: null,
        cvss_v2_score: "10.0",
        exact_version: "1.24.13",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("blocked");
  });

  it("does not block on a v2-only score below the threshold", () => {
    const rows = [
      affects({
        cve_id: "CVE-V2-HIGH",
        severity: "HIGH",
        severity_source: "nvd-cvss-v2",
        cvss_v3_score: null,
        cvss_v2_score: "8.9",
        exact_version: "1.24.13",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("available");
  });

  it("blocks on a v4-only score >= 9.0", () => {
    const rows = [
      affects({
        cve_id: "CVE-V4-CRIT",
        severity: "CRITICAL",
        severity_source: "nvd-cvss-v4",
        cvss_v3_score: null,
        cvss_v4_score: "9.5",
        exact_version: "1.24.13",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("blocked");
  });

  it("blocks when v3 sits below the gate but another version's score crosses it (any-of)", () => {
    const rows = [
      affects({
        cve_id: "CVE-MIXED",
        severity: "HIGH",
        cvss_v3_score: "7.5",
        cvss_v2_score: "9.3",
        exact_version: "1.24.13",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("blocked");
  });

  it("does not block on KEV alone — exploited-in-the-wild is signal, not a blocker", () => {
    const rows = [
      affects({
        cve_id: "CVE-KEV",
        severity: "HIGH",
        cvss_v3_score: "7.8",
        is_kev: true,
        exact_version: "1.24.13",
        version_end: null,
      }),
    ];
    expect(getVersionAvailabilityStatus("1.24.13", rows)).toBe("available");
  });

  it("keeps a suppressed critical CVE visible but excludes it from the gate", () => {
    const row = affects({
      cve_id: "CVE-SUPPRESSED",
      severity: "CRITICAL",
      cvss_v3_score: "9.8",
      exact_version: "1.24.13",
      version_end: null,
      suppressed: true,
      suppression_id: 42,
      suppression_reason: "Confirmed upstream mis-attribution",
      suppression_created_by: "operator@example.com",
      suppression_expires_at: null,
    });
    expect(getVersionAvailabilityStatus("1.24.13", [row])).toBe("available");
    expect(findBlockingCve("1.24.13", [row])).toBeNull();

    const [version] = crossReferenceVersions(
      [{ version: "1.24.13", version_group: "1.24" }],
      [row],
    );
    expect(version.vulns[0]).toMatchObject({
      cve_id: "CVE-SUPPRESSED",
      suppression: {
        id: 42,
        reason: "Confirmed upstream mis-attribution",
        created_by: "operator@example.com",
        package_name: null,
        expires_at: null,
      },
    });
  });
});

// WAL-79: the gate computes an explanation while deciding; the download route quotes it back in
// the 403. These tests pin the explanation itself — that it exists, that it says the right thing,
// and that it is the same explanation twice for the same data.
describe("findBlockingCveMatch", () => {
  const CRIT = {
    cve_id: "CVE-CRIT",
    cvss_v3_score: "9.8",
    severity: "CRITICAL",
    exact_version: "1.24.13",
    version_end: null,
  };

  it("returns the comparison that matched alongside the row", () => {
    const match = findBlockingCveMatch("1.24.13", [affects(CRIT)]);
    expect(match?.cve.cve_id).toBe("CVE-CRIT");
    expect(match?.matched_because).toBe("1.24.13 == 1.24.13");
  });

  it("says so when normalisation changed what was compared (ADR-008)", () => {
    const rows = [
      affects({
        cve_id: "CVE-CRIT",
        cvss_v3_score: "9.8",
        exact_version: "2.55.0",
        version_end: null,
        cve_version_extract: "^(\\d+\\.\\d+\\.\\d+)",
      }),
    ];
    // The whole point of the field: a 2.55.0.5 refused by a range naming 2.55.0 has to read as
    // policy rather than as a bug.
    expect(findBlockingCveMatch("2.55.0.5", rows)?.matched_because).toBe(
      "2.55.0 == 2.55.0 (2.55.0.5 evaluated as 2.55.0)",
    );
  });

  it("returns null for a servable version and for a suppressed critical", () => {
    expect(findBlockingCveMatch("1.24.12", [affects(CRIT)])).toBeNull();
    expect(findBlockingCveMatch("1.24.13", [affects({ ...CRIT, suppressed: true })])).toBeNull();
  });

  // AC6: the affects loader's ORDER BY is not the gate's contract. Two callers holding the same
  // rows in a different order must be told the same thing, or walrus appears to change its mind.
  it("names the same CVE whatever order the rows arrive in", () => {
    const rows = [
      affects({ ...CRIT, cve_id: "CVE-2026-0002", cvss_v3_score: "9.1" }),
      affects({ ...CRIT, cve_id: "CVE-2026-0001", cvss_v3_score: "9.9" }),
      affects({ ...CRIT, cve_id: "CVE-2026-0003", cvss_v3_score: "9.4" }),
    ];
    for (const order of [rows, [...rows].reverse(), [rows[2], rows[0], rows[1]]]) {
      expect(findBlockingCveMatch("1.24.13", order)?.cve.cve_id).toBe("CVE-2026-0001");
    }
  });

  // Ranking on v3 alone would hand the block to the 9.0 and misreport the more severe advisory,
  // when the gate itself thresholds any-of across CVSS versions (ADR-005).
  it("ranks on the highest score across CVSS versions, not on v3", () => {
    const rows = [
      affects({ ...CRIT, cve_id: "CVE-V3", cvss_v3_score: "9.0" }),
      affects({
        ...CRIT,
        cve_id: "CVE-V4",
        cvss_v3_score: null,
        cvss_v4_score: "9.9",
        severity_source: "nvd-cvss-v4",
      }),
    ];
    expect(findBlockingCveMatch("1.24.13", rows)?.cve.cve_id).toBe("CVE-V4");
  });

  it("breaks an equal-score tie towards the exploited-in-the-wild advisory", () => {
    const rows = [
      affects({ ...CRIT, cve_id: "CVE-2026-0001" }),
      affects({ ...CRIT, cve_id: "CVE-2026-0002", is_kev: true }),
    ];
    expect(findBlockingCveMatch("1.24.13", rows)?.cve.cve_id).toBe("CVE-2026-0002");
  });

  it("keeps findBlockingCve as the row-only view of the same decision", () => {
    const rows = [
      affects({ ...CRIT, cve_id: "CVE-2026-0002", cvss_v3_score: "9.1" }),
      affects({ ...CRIT, cve_id: "CVE-2026-0001", cvss_v3_score: "9.9" }),
    ];
    expect(findBlockingCve("1.24.13", rows)).toBe(findBlockingCveMatch("1.24.13", rows)?.cve);
    expect(findBlockingCve("1.24.12", rows)).toBeNull();
  });
});

describe("CPE version NA is not ANY (WAL-69)", () => {
  /** CVE-2024-43488's real shape: NA version, no bounds, NVD-rescored to 9.8 CRITICAL. */
  const naCritical = affects({
    cve_id: "CVE-2024-43488",
    version_na: true,
    version_start: null,
    version_end: null,
    exact_version: null,
    fixed_in: null,
    severity: "CRITICAL",
    cvss_v3_score: "9.8",
  });

  /** Same absence of bounds, but ANY rather than NA — this one genuinely means all versions. */
  const anyCritical = affects({
    cve_id: "CVE-2099-9999",
    version_na: false,
    version_start: null,
    version_end: null,
    exact_version: null,
    fixed_in: null,
    severity: "CRITICAL",
    cvss_v3_score: "9.8",
  });

  it("does not block a version on a CPE that names no version", () => {
    expect(getVersionAvailabilityStatus("1.135.0", [naCritical])).toBe("available");
    expect(findBlockingCve("1.135.0", [naCritical])).toBeNull();
  });

  it("still blocks on an unbounded ANY CPE — the reading the fix must preserve", () => {
    expect(getVersionAvailabilityStatus("1.135.0", [anyCritical])).toBe("blocked");
    expect(findBlockingCve("1.135.0", [anyCritical])?.cve_id).toBe("CVE-2099-9999");
  });

  it("blocks on the ANY row even when an NA row is evaluated first", () => {
    // Ordering must not decide the answer: the NA row is skipped, not treated as a match
    // that short-circuits the loop.
    expect(findBlockingCve("1.135.0", [naCritical, anyCritical])?.cve_id).toBe("CVE-2099-9999");
  });

  it("keeps the NA advisory visible, under its own reason", () => {
    const [v] = crossReferenceVersions([{ version: "1.135.0", version_group: "1" }], [naCritical]);
    expect(v.counts.total).toBe(1);
    expect(v.counts.critical).toBe(1);
    expect(v.vulns[0]).toMatchObject({
      cve_id: "CVE-2024-43488",
      matched_because: VERSION_NA,
    });
  });

  it("prefers a concrete range match over the NA reason for the same CVE", () => {
    const rows = [
      affects({ cve_id: "CVE-DUAL", version_na: true, version_start: null, version_end: null }),
      affects({ cve_id: "CVE-DUAL", version_end: "9.0", version_end_excl: true }),
    ];
    const [v] = crossReferenceVersions([{ version: "8.0", version_group: "8" }], rows);
    expect(v.vulns).toHaveLength(1);
    expect(v.vulns[0].matched_because).not.toBe(VERSION_NA);
  });

  it("leaves latest_available populated when only NA rows are critical", () => {
    const groups = summarizeGroupsWithVulnGate(
      [
        { version: "1.135.0", version_group: "1", is_lts: false },
        { version: "1.134.0", version_group: "1", is_lts: false },
      ],
      [naCritical],
    );
    expect(groups[0].latest_available).toBe("1.135.0");
  });

  it("still gates a version-bounded critical alongside NA rows", () => {
    // vscode's real mix: NA rows that must not gate, plus CVE-2026-47281 which must.
    const bounded = affects({
      cve_id: "CVE-2026-47281",
      version_na: false,
      version_start: "1.0.0",
      version_end: "1.123.1",
      version_end_excl: true,
      exact_version: null,
      severity: "CRITICAL",
      cvss_v3_score: "9.6",
    });
    expect(findBlockingCve("1.135.0", [naCritical, bounded])).toBeNull();
    expect(findBlockingCve("1.100.0", [naCritical, bounded])?.cve_id).toBe("CVE-2026-47281");
  });
});
