import { describe, it, expect } from "vitest";
import { crossReferenceVersions } from "../../src/services/vuln-service.js";
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
