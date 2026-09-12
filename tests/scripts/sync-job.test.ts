import { describe, expect, it } from "vitest";
import { parsePackageArg, parseJobIdArg } from "../../src/commands/sync-job.js";

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

describe("sync-job --job-id parsing", () => {
  it("returns undefined when not given, meaning create a fresh job row", () => {
    expect(parseJobIdArg([])).toBeUndefined();
  });

  it("reads the id as a number", () => {
    expect(parseJobIdArg(["--job-id", "708"])).toBe(708);
  });

  it("rejects a non-integer value", () => {
    expect(() => parseJobIdArg(["--job-id", "seven"])).toThrow(/positive integer/);
    expect(() => parseJobIdArg(["--job-id", "7.5"])).toThrow(/positive integer/);
    expect(() => parseJobIdArg(["--job-id", "0"])).toThrow(/positive integer/);
    expect(() => parseJobIdArg(["--job-id", "-1"])).toThrow(/positive integer/);
  });

  it("rejects a bare --job-id with no value", () => {
    expect(() => parseJobIdArg(["--job-id"])).toThrow(/positive integer/);
  });

  it("rejects a following flag being taken as the id", () => {
    expect(() => parseJobIdArg(["--job-id", "--package"])).toThrow(/positive integer/);
  });
});
