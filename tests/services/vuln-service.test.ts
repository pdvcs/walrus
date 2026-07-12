import { describe, it, expect } from "vitest";
import {
  crossReferenceVersions,
  getVersionAvailabilityStatus,
  summarizeGroupsWithVulnGate,
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
    cvss_v3_score: "7.5",
    description: null,
    is_kev: false,
    raw: null,
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
});
