import { describe, expect, it } from "vitest";
import { buildMatchString, escapeCpeComponent, parseCpe } from "../../src/vuln/cpe.js";

describe("parseCpe", () => {
  it("parses a plain CPE string", () => {
    const p = parseCpe("cpe:2.3:a:nodejs:node.js:18.12.0:*:*:*:*:*:*:*");
    expect(p).toMatchObject({
      part: "a",
      vendor: "nodejs",
      product: "node.js",
      version: "18.12.0",
    });
  });

  it("handles escaped plus signs in the product component", () => {
    const p = parseCpe("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+:*:*:*:*:*:*:*:*");
    expect(p).toMatchObject({ vendor: "notepad-plus-plus", product: "notepad++", version: "*" });
  });

  it("handles escaped colons inside a component", () => {
    const p = parseCpe("cpe:2.3:a:weird\\:vendor:prod:1.0:*:*:*:*:*:*:*");
    expect(p).toMatchObject({ vendor: "weird:vendor", product: "prod", version: "1.0" });
  });

  it("returns null for non-CPE strings", () => {
    expect(parseCpe("not-a-cpe")).toBeNull();
    expect(parseCpe("cpe:2.2:a:x:y:1")).toBeNull();
  });

  it("extracts an exact version when present", () => {
    const p = parseCpe("cpe:2.3:a:golang:go:1.21.0:*:*:*:*:*:*:*");
    expect(p?.version).toBe("1.21.0");
  });
});

describe("escapeCpeComponent / buildMatchString", () => {
  it("escapes plus signs", () => {
    expect(escapeCpeComponent("notepad++")).toBe("notepad\\+\\+");
  });

  it("leaves dots, dashes, underscores alone", () => {
    expect(escapeCpeComponent("node.js")).toBe("node.js");
    expect(escapeCpeComponent("intellij_idea")).toBe("intellij_idea");
    expect(escapeCpeComponent("notepad-plus-plus")).toBe("notepad-plus-plus");
  });

  it("builds a match string that round-trips through parseCpe", () => {
    const ms = buildMatchString("notepad-plus-plus", "notepad++");
    expect(ms).toBe("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+");
    const p = parseCpe(ms + ":*:*:*:*:*:*:*:*");
    expect(p).toMatchObject({ vendor: "notepad-plus-plus", product: "notepad++" });
  });
});
