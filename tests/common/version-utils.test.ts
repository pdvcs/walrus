import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  extractVersionGroup,
  applyTagPattern,
  generateSortKey,
  compareVersions,
  sortVersionsDesc,
  parseVersion,
} from "../../src/common/version-utils.js";

describe("extractVersionGroup", () => {
  it("extracts major version group for Java-style", () => {
    expect(extractVersionGroup("21.0.3+9", "^(\\d+)")).toBe("21");
    expect(extractVersionGroup("17.0.8+7", "^(\\d+)")).toBe("17");
    expect(extractVersionGroup("11.0.21+9", "^(\\d+)")).toBe("11");
  });

  it("extracts major.minor version group for Go-style", () => {
    expect(extractVersionGroup("1.24.1", "^(\\d+\\.\\d+)")).toBe("1.24");
    expect(extractVersionGroup("1.23.5", "^(\\d+\\.\\d+)")).toBe("1.23");
  });

  it("extracts major.minor for uv-style pre-1.0", () => {
    expect(extractVersionGroup("0.6.2", "^(\\d+\\.\\d+)")).toBe("0.6");
    expect(extractVersionGroup("0.5.29", "^(\\d+\\.\\d+)")).toBe("0.5");
  });

  it("returns null when regex does not match", () => {
    expect(extractVersionGroup("abc", "^(\\d+)")).toBeNull();
    expect(extractVersionGroup("", "^(\\d+)")).toBeNull();
  });
});

describe("applyTagPattern", () => {
  it('strips "go" prefix', () => {
    expect(applyTagPattern("go1.24.1", "^go(\\d+.*)")).toBe("1.24.1");
  });

  it('strips "v" prefix', () => {
    expect(applyTagPattern("v1.2.3", "^v(\\d+.*)")).toBe("1.2.3");
  });

  it("returns null when no match", () => {
    expect(applyTagPattern("1.2.3", "^go(\\d+.*)")).toBeNull();
  });
});

describe("generateSortKey", () => {
  it("pads standard semver segments", () => {
    const k = generateSortKey("1.24.1");
    expect(k).toBe("000001.000024.000001~");
  });

  it("handles build metadata by ignoring it for sort", () => {
    const k1 = generateSortKey("21.0.3+9");
    const k2 = generateSortKey("21.0.3+12");
    // Both should produce the same key (build metadata ignored for sorting)
    expect(k1).toBe(k2);
  });

  it("sorts correctly: higher version → higher key", () => {
    const k21 = generateSortKey("21.0.3");
    const k17 = generateSortKey("17.0.8");
    expect(k21 > k17).toBe(true);
  });

  it("sorts correctly for patch versions", () => {
    const k3 = generateSortKey("1.24.3");
    const k1 = generateSortKey("1.24.1");
    expect(k3 > k1).toBe(true);
  });

  it("orders pre-release below release", () => {
    const pre = generateSortKey("1.0.0-alpha.1");
    const release = generateSortKey("1.0.0");
    expect(pre < release).toBe(true);
  });

  it("pads a version shorter than three components", () => {
    expect(generateSortKey("2026.2")).toBe("002026.000002.000000~");
    // ...which is deliberately the same key as its own zero-filled form.
    expect(generateSortKey("2026.2")).toBe(generateSortKey("2026.2.0"));
  });

  it("keys a fourth component as a continuation of the third", () => {
    expect(generateSortKey("2025.3.6.1")).toBe("002025.000003.000006~000001~");
    expect(generateSortKey("2025.3.6.1.4")).toBe("002025.000003.000006~000001~000004~");
  });

  it("keys are byte-identical for everything semver parses", () => {
    // WAL-63 AC5: the fix is confined to the non-semver branch, so no stored key for a
    // semver-shaped version moves. Guarding it here means a future edit to the semver branch
    // has to be a deliberate one that also migrates `versions.version_sort`.
    expect(generateSortKey("1.24.1")).toBe("000001.000024.000001~");
    expect(generateSortKey("21.0.3+9")).toBe("000021.000000.000003~");
    expect(generateSortKey("4.0.0-rc-4")).toBe("000004.000000.000000-rc-4");
    expect(generateSortKey("1.0.0-alpha.1")).toBe("000001.000000.000000-alpha.000001");
  });
});

describe("generateSortKey ordering (WAL-63)", () => {
  it("ranks a four-component build above the three-component version it extends", () => {
    expect(sortVersionsDesc(["2025.3.6", "2025.3.6.1"])).toEqual(["2025.3.6.1", "2025.3.6"]);
    expect(sortVersionsDesc(["2025.2.6.2", "2025.2.6", "2025.2.6.3"])).toEqual([
      "2025.2.6.3",
      "2025.2.6.2",
      "2025.2.6",
    ]);
  });

  it("interleaves component counts within one group", () => {
    expect(sortVersionsDesc(["2026.2", "2026.2.0.1", "2026.2.1"])).toEqual([
      "2026.2.1",
      "2026.2.0.1",
      "2026.2",
    ]);
  });

  it("keys a fourth component the loose semver parser mis-reads", () => {
    // semver loose turns "1.2.10.1" into 1.2.1-0.1 — a key below 1.2.2, for a build above
    // 1.2.10. The sorter must not consult it for four-component versions.
    expect(sortVersionsDesc(["1.2.10", "1.2.10.1", "1.2.11"])).toEqual([
      "1.2.11",
      "1.2.10.1",
      "1.2.10",
    ]);
    expect(generateSortKey("0.0.10.0") > generateSortKey("0.0.10")).toBe(true);
  });

  it("keeps pre-releases below their release across component counts", () => {
    expect(compareVersions("1.2.3-rc1", "1.2.3")).toBeLessThan(0);
    expect(compareVersions("2025.3.6.1-eap", "2025.3.6.1")).toBeLessThan(0);
    // ...and still above the shorter version the pre-release extends.
    expect(compareVersions("2025.3.6.1-eap", "2025.3.6")).toBeGreaterThan(0);
  });

  it("orders the real IntelliJ IDEA window by release date", () => {
    // Upstream dates, verified 2026-08-27 (engineering/plans/intellij-idea-onboarding.md).
    const byDate = ["2025.3.6.1", "2025.3.6", "2025.2.6.3", "2025.2.6.2"];
    expect(sortVersionsDesc(["2025.2.6.2", "2025.3.6", "2025.3.6.1", "2025.2.6.3"])).toEqual(
      byDate,
    );
  });

  it("orders the Git for Windows revision ladder (WAL-60)", () => {
    // gitwindows is the first served package whose version carries a fourth component
    // (.windows.N rebuild revisions). Across a minor bump...
    expect(sortVersionsDesc(["2.54.0.9", "2.55.0.1"])).toEqual(["2.55.0.1", "2.54.0.9"]);
    // ...and across a two-digit revision: .9 must not outrank .10 lexicographically.
    expect(sortVersionsDesc(["2.55.0.9", "2.55.0.10"])).toEqual(["2.55.0.10", "2.55.0.9"]);
    // The first build of a series ships a three-component version (Git-2.55.0-...); its
    // later rebuilds extend it.
    expect(sortVersionsDesc(["2.55.0.2", "2.55.0", "2.55.0.5"])).toEqual([
      "2.55.0.5",
      "2.55.0.2",
      "2.55.0",
    ]);
    // The revision ladder sits between series bumps.
    expect(sortVersionsDesc(["2.55.0.4", "2.56.0.1", "2.55.0.5"])).toEqual([
      "2.56.0.1",
      "2.55.0.5",
      "2.55.0.4",
    ]);
  });
});

describe("generateSortKey property: mixed component counts", () => {
  /**
   * Reference ordering: read a version shorter than three components as though the missing
   * ones were zero (`2026.2` is `2026.2.0`, the reading semver gives it), then compare
   * component-wise. When one is a prefix of the other the shorter ranks lower — `1.2.3.0` is a
   * later build than `1.2.3`, not the same one.
   */
  function normalize(components: number[]): number[] {
    return components.length >= 3 ? components : [...components, 0, 0].slice(0, 3);
  }

  function referenceCompare(a: number[], b: number[]): number {
    const [x, y] = [normalize(a), normalize(b)];
    for (let i = 0; i < Math.min(x.length, y.length); i++) {
      if (x[i] !== y[i]) return x[i] - y[i];
    }
    return x.length - y.length;
  }

  const versionArb = fc
    .array(fc.integer({ min: 0, max: 999_999 }), { minLength: 2, maxLength: 5 })
    .map((components) => ({ components, text: components.join(".") }));

  it("agrees with a component-wise reference ordering for 2-5 segments", () => {
    fc.assert(
      fc.property(fc.array(versionArb, { minLength: 2, maxLength: 12 }), (generated) => {
        // Distinct versions only: `2026.2` and `2026.2.0` are one version under the reference
        // ordering, so their relative order carries no information to check.
        const seen = new Set<string>();
        const versions = generated.filter((v) => {
          const key = normalize(v.components).join(".");
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        const byKey = [...versions].sort((x, y) =>
          generateSortKey(x.text) < generateSortKey(y.text) ? -1 : 1,
        );
        const byReference = [...versions].sort((x, y) =>
          referenceCompare(x.components, y.components),
        );
        expect(byKey.map((v) => v.text)).toEqual(byReference.map((v) => v.text));
      }),
      { numRuns: 500 },
    );
  });

  it("gives a strict numeric extension a strictly greater key", () => {
    fc.assert(
      fc.property(
        versionArb,
        fc.array(fc.integer({ min: 0, max: 999_999 }), { minLength: 1, maxLength: 3 }),
        (base, extension) => {
          const components = [...base.components, ...extension];
          const extended = components.join(".");
          // Equal only when the extension does nothing but fill the implicit zeros of a
          // shorter-than-three-component version; otherwise strictly greater.
          const expectedStrict =
            normalize(components).join(".") !== normalize(base.components).join(".");
          expect(generateSortKey(base.text) < generateSortKey(extended)).toBe(expectedStrict);
          expect(generateSortKey(base.text) <= generateSortKey(extended)).toBe(true);
        },
      ),
      { numRuns: 500 },
    );
  });

  it("byte comparison and localeCompare agree over the key alphabet", () => {
    // `selectRetentionWindow` orders keys with localeCompare while SQL and the rest of the
    // codebase use byte comparison; retention would pick different versions if they disagreed.
    fc.assert(
      fc.property(versionArb, versionArb, (a, b) => {
        const ka = generateSortKey(a.text);
        const kb = generateSortKey(b.text);
        expect(Math.sign(ka.localeCompare(kb))).toBe(Math.sign(ka < kb ? -1 : ka > kb ? 1 : 0));
      }),
      { numRuns: 500 },
    );
  });
});

describe("compareVersions", () => {
  it("returns negative when a < b", () => {
    expect(compareVersions("1.0.0", "2.0.0")).toBeLessThan(0);
    expect(compareVersions("1.23.0", "1.24.0")).toBeLessThan(0);
  });

  it("returns positive when a > b", () => {
    expect(compareVersions("21.0.3", "17.0.8")).toBeGreaterThan(0);
    expect(compareVersions("1.24.5", "1.24.1")).toBeGreaterThan(0);
  });

  it("returns 0 for equal versions", () => {
    expect(compareVersions("1.2.3", "1.2.3")).toBe(0);
  });

  it("handles build metadata as equal for comparison", () => {
    // 21.0.3+9 and 21.0.3+12 should compare as equal (build ignored)
    expect(compareVersions("21.0.3+9", "21.0.3+12")).toBe(0);
  });
});

describe("sortVersionsDesc", () => {
  it("sorts semver versions newest first", () => {
    const versions = ["1.0.0", "2.0.0", "1.5.0", "1.0.1"];
    expect(sortVersionsDesc(versions)).toEqual(["2.0.0", "1.5.0", "1.0.1", "1.0.0"]);
  });

  it("sorts Go-style versions correctly", () => {
    const versions = ["1.24.1", "1.23.5", "1.24.0", "1.22.10"];
    expect(sortVersionsDesc(versions)).toEqual(["1.24.1", "1.24.0", "1.23.5", "1.22.10"]);
  });

  it("does not mutate the original array", () => {
    const versions = ["1.0.0", "2.0.0"];
    const sorted = sortVersionsDesc(versions);
    expect(versions).toEqual(["1.0.0", "2.0.0"]);
    expect(sorted).toEqual(["2.0.0", "1.0.0"]);
  });
});

describe("parseVersion", () => {
  it("strips v prefix", () => {
    expect(parseVersion("v1.2.3")).toBe("1.2.3");
    expect(parseVersion("v0.6.2")).toBe("0.6.2");
  });

  it("returns version unchanged when no v prefix", () => {
    expect(parseVersion("1.2.3")).toBe("1.2.3");
    expect(parseVersion("21.0.3+9")).toBe("21.0.3+9");
  });
});
