import { describe, expect, it } from "vitest";
import { parsePackageArg } from "../../src/commands/sync-job.js";

describe("sync-job --package parsing", () => {
  it("returns undefined when no package is given, meaning every package", () => {
    expect(parsePackageArg([])).toBeUndefined();
  });

  it("reads the package name", () => {
    expect(parsePackageArg(["--package", "golang"])).toBe("golang");
  });

  it("rejects a bare --package with no value", () => {
    expect(() => parsePackageArg(["--package"])).toThrow(/requires a package name/);
  });

  it("rejects a following flag being taken as the package name", () => {
    // Without this, `--package --dry-run` would silently sync a package called "--dry-run",
    // which resolves to nothing and reports a successful no-op run.
    expect(() => parsePackageArg(["--package", "--dry-run"])).toThrow(/requires a package name/);
  });
});
