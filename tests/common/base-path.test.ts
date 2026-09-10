import { describe, it, expect } from "vitest";
import { withBase, isValidBasePath } from "../../src/common/base-path.js";

describe("withBase", () => {
  it("passes an absolute path through unchanged when there is no base path", () => {
    expect(withBase("", "/admin/v1/")).toBe("/admin/v1/");
  });

  it("prefixes with a single-segment base path", () => {
    expect(withBase("/foo", "/admin/v1/")).toBe("/foo/admin/v1/");
    expect(withBase("/foo", "/health")).toBe("/foo/health");
  });

  it("prefixes with a multi-segment base path", () => {
    expect(withBase("/corp/walrus", "/download/uv/0.6.2/linux/x86-64")).toBe(
      "/corp/walrus/download/uv/0.6.2/linux/x86-64",
    );
  });
});

describe("isValidBasePath", () => {
  it("accepts empty string (root — today's default)", () => {
    expect(isValidBasePath("")).toBe(true);
  });

  it("accepts a single path segment", () => {
    expect(isValidBasePath("/foo")).toBe(true);
    expect(isValidBasePath("/bar")).toBe(true);
    expect(isValidBasePath("/foo-bar_baz")).toBe(true);
    expect(isValidBasePath("/foo123")).toBe(true);
  });

  it("accepts a multi-segment path (nice-to-have, not the priority case)", () => {
    expect(isValidBasePath("/corp/walrus")).toBe(true);
  });

  it("rejects a value with no leading slash", () => {
    expect(isValidBasePath("foo")).toBe(false);
  });

  it("rejects a trailing slash", () => {
    expect(isValidBasePath("/foo/")).toBe(false);
  });

  it("rejects the root slash alone", () => {
    expect(isValidBasePath("/")).toBe(false);
  });

  it("rejects a doubled slash", () => {
    expect(isValidBasePath("/foo//bar")).toBe(false);
  });

  it("rejects a segment with disallowed characters", () => {
    expect(isValidBasePath("/foo bar")).toBe(false);
    expect(isValidBasePath("/foo?bar")).toBe(false);
  });
});
