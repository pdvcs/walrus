import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  compareVersions,
  describeRange,
  evaluateRange,
  isComparable,
} from "../../src/vuln/version-ranges.js";

describe("compareVersions (table-driven)", () => {
  const LT: Array<[string, string]> = [
    ["8.3.2", "8.5.6"],
    ["8.5.6", "8.5.7"],
    ["1.0", "1.0b"], // trailing alpha sorts after base
    ["1.0a", "1.0b"],
    ["0.9", "1.0"],
    ["1.9", "1.10"], // numeric, not lexical
    ["21.07", "21.7.1"], // 07 == 7 numerically, then extra segment
    ["2021.1", "2021.2"],
    ["2021.1", "2022.1"],
    ["1.0.rc1", "1.0.1"], // alpha vs numeric at same position
    ["8.3.2", "8.3.2.1"],
    ["5", "10"],
    ["1.2.3", "v1.2.4"], // leading v stripped
    ["18.12.0", "18.12.1"],
    ["1.21.0", "1.21.13"],
    ["3.11.9", "3.12.0"],
    ["1.5.4", "1.6.0"],
    ["7.7", "8.4.5"],
  ];
  it.each(LT)("%s < %s", (a, b) => {
    expect(compareVersions(a, b)).toBe(-1);
    expect(compareVersions(b, a)).toBe(1); // antisymmetric
  });

  const EQ: Array<[string, string]> = [
    ["8.3.2", "8.3.2"],
    ["8.3.2", "v8.3.2"],
    ["8.3.2.0", "8.3.2"], // trailing zeros insignificant
    ["8.3.2.0.0", "8.3.2"],
    ["21.07", "21.7"], // leading zero in numeric segment
    ["1.0", "1.0.0"],
    ["1_0", "1.0"], // underscore separator
    ["1-0", "1.0"], // dash separator
    [" 8.3.2 ", "8.3.2"], // whitespace
    ["V8.3.2", "8.3.2"], // uppercase V
  ];
  it.each(EQ)("%s == %s", (a, b) => {
    expect(compareVersions(a, b)).toBe(0);
    expect(compareVersions(b, a)).toBe(0);
  });

  const UNCOMPARABLE = ["banana", "", "   ", "x.y.z"];
  it.each(UNCOMPARABLE)('"%s" is uncomparable', (v) => {
    expect(compareVersions(v, "1.0")).toBeNull();
    expect(compareVersions("1.0", v)).toBeNull();
    expect(isComparable(v)).toBe(false);
  });

  // Pre-release ordering: semver-valid strings follow semver, everything else
  // keeps the fallback's "extra alpha segment is a later build" rule.
  //
  // This deliberately reverses an earlier documented trade-off, which assumed
  // "true semver pre-release strings are rare in CPE data". They are not rare in
  // OSV data, which supplies bounds like ">=1.27.0-0 <1.27.0-rc.3" — and under
  // the old rule the released 1.27.0 fell *inside* that range.
  it("semver pre-releases sort BEFORE their base release", () => {
    expect(compareVersions("1.0.0-alpha", "1.0.0")).toBe(-1);
    expect(compareVersions("1.27.0", "1.27.0-rc.3")).toBe(1);
    expect(compareVersions("1.27.0-rc.3", "1.27.0")).toBe(-1);
    // ...and order among themselves
    expect(compareVersions("1.27.0-rc.1", "1.27.0-rc.3")).toBe(-1);
    // "-0" is the lowest pre-release; OSV emits it for "any version in this line"
    expect(compareVersions("1.27.0", "1.27.0-0")).toBe(1);
    expect(compareVersions("1.26.0-rc.1", "1.26.0-0")).toBe(1);
  });

  it("non-semver alpha suffixes still sort AFTER the base (vendor versions)", () => {
    // The case the original trade-off existed for: "1.0b" is not valid semver,
    // so it never reaches the strict comparator and keeps the fallback ordering.
    expect(compareVersions("1.0b", "1.0")).toBe(1);
    expect(compareVersions("1.0", "1.0b")).toBe(-1);
    expect(compareVersions("1.0.rc1", "1.0.1")).toBe(-1);
  });
});

describe("comparator properties (fast-check)", () => {
  const versionArb = fc
    .array(fc.nat({ max: 99 }), { minLength: 1, maxLength: 5 })
    .map((segs) => segs.join("."));
  const messyVersionArb = fc
    .tuple(versionArb, fc.constantFrom("", "a", "b", "rc1", "beta"))
    .map(([v, suffix]) => (suffix ? `${v}${suffix}` : v));

  it("never crashes and is antisymmetric", () => {
    fc.assert(
      fc.property(messyVersionArb, messyVersionArb, (a, b) => {
        const ab = compareVersions(a, b);
        const ba = compareVersions(b, a);
        expect(ab).not.toBeNull();
        expect(ba).not.toBeNull();
        expect(ab! + ba!).toBe(0);
      }),
    );
  });

  it("is reflexive", () => {
    fc.assert(
      fc.property(messyVersionArb, (a) => {
        expect(compareVersions(a, a)).toBe(0);
      }),
    );
  });

  it("is transitive on parseable versions", () => {
    fc.assert(
      fc.property(versionArb, versionArb, versionArb, (a, b, c) => {
        const ab = compareVersions(a, b)!;
        const bc = compareVersions(b, c)!;
        const ac = compareVersions(a, c)!;
        if (ab <= 0 && bc <= 0) expect(ac).toBeLessThanOrEqual(0);
        if (ab >= 0 && bc >= 0) expect(ac).toBeGreaterThanOrEqual(0);
      }),
    );
  });

  it("returns null (never throws) for arbitrary junk strings", () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        // Must not throw regardless of input.
        expect(() => compareVersions(a, b)).not.toThrow();
      }),
    );
  });
});

describe("evaluateRange", () => {
  const base = {
    versionStart: null,
    versionStartExcl: false,
    versionEnd: null,
    versionEndExcl: true,
    exactVersion: null,
  };

  it("end-including: 8.3.2 <= 8.5.6 matches, 8.6.0 does not", () => {
    const range = { ...base, versionEnd: "8.5.6", versionEndExcl: false };
    expect(evaluateRange("8.3.2", range)).toEqual({ matched: true, reason: "8.3.2 <= 8.5.6" });
    expect(evaluateRange("8.6.0", range).matched).toBe(false);
    expect(evaluateRange("8.5.6", range).matched).toBe(true); // boundary included
  });

  it("end-excluding: boundary version does NOT match", () => {
    const range = { ...base, versionEnd: "8.5.6", versionEndExcl: true };
    expect(evaluateRange("8.5.6", range).matched).toBe(false);
    expect(evaluateRange("8.5.5", range).matched).toBe(true);
  });

  it("start-including and start-excluding boundaries", () => {
    expect(evaluateRange("1.0", { ...base, versionStart: "1.0" }).matched).toBe(true);
    expect(
      evaluateRange("1.0", { ...base, versionStart: "1.0", versionStartExcl: true }).matched,
    ).toBe(false);
    expect(evaluateRange("0.9", { ...base, versionStart: "1.0" }).matched).toBe(false);
  });

  it("exact version match", () => {
    const range = { ...base, exactVersion: "2.1.0" };
    expect(evaluateRange("2.1.0", range).matched).toBe(true);
    expect(evaluateRange("2.1.1", range).matched).toBe(false);
    expect(evaluateRange("v2.1.0", range).matched).toBe(true); // normalized
  });

  it("fails open with range-uncomparable for unparseable versions", () => {
    const range = { ...base, versionEnd: "8.5.6" };
    expect(evaluateRange("lots-of-nonsense", range)).toEqual({
      matched: true,
      reason: "range-uncomparable",
    });
  });

  // Regression for CVE-2026-39821 on golang: the range covers only 1.27.0's
  // release candidates, but the released 1.27.0 was matching it and returning a
  // 403 from /download. The RCs the range does target were excluded.
  it("a pre-release-bounded range excludes the released version (CVE-2026-39821)", () => {
    const range = {
      ...base,
      versionStart: "1.27.0-0",
      versionEnd: "1.27.0-rc.3",
      versionEndExcl: true,
    };
    expect(evaluateRange("1.27.0", range).matched).toBe(false);
    expect(evaluateRange("1.27.0-rc.1", range).matched).toBe(true);
    expect(evaluateRange("1.27.0-rc.3", range).matched).toBe(false); // end-excluded
  });

  it("still matches the same CVE's correct range (guards against over-correcting)", () => {
    const range = { ...base, versionStart: "1.26.0-0", versionEnd: "1.26.6", versionEndExcl: true };
    expect(evaluateRange("1.26.4", range).matched).toBe(true);
    expect(evaluateRange("1.26.5", range).matched).toBe(true);
    expect(evaluateRange("1.26.6", range).matched).toBe(false);
    expect(evaluateRange("1.26.7", range).matched).toBe(false);
  });

  it("empty range means all versions", () => {
    expect(evaluateRange("1.2.3", base)).toEqual({ matched: true, reason: "all-versions" });
  });
});

describe("describeRange", () => {
  const base = {
    versionStart: null,
    versionStartExcl: false,
    versionEnd: null,
    versionEndExcl: true,
    exactVersion: null,
  };
  it("formats bounds and exact versions", () => {
    expect(describeRange({ ...base, versionEnd: "8.5.6", versionEndExcl: false })).toBe("<= 8.5.6");
    expect(describeRange({ ...base, versionEnd: "8.5.6" })).toBe("< 8.5.6");
    expect(describeRange({ ...base, versionStart: "1.0", versionEnd: "2.0" })).toBe(
      ">= 1.0, < 2.0",
    );
    expect(describeRange({ ...base, exactVersion: "3.1" })).toBe("== 3.1");
    expect(describeRange(base)).toBe("all versions");
  });
});
