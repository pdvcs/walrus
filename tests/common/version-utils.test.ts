import { describe, it, expect } from "vitest";
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
