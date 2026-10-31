import { describe, expect, it } from "vitest";
import {
  buildMatchString,
  escapeCpeComponent,
  isCpeExcluded,
  parseCpe,
} from "../../src/vuln/cpe.js";

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

  it("reads the qualifier components that tell one product from another", () => {
    // Terraform Enterprise: same vendor:product as the CLI, distinguished only by target_sw.
    expect(parseCpe("cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:enterprise:*:*")).toMatchObject({
      edition: "*",
      language: "*",
      sw_edition: "*",
      target_sw: "enterprise",
      target_hw: "*",
      other: "*",
    });
    // Gradle Enterprise uses sw_edition instead.
    expect(parseCpe("cpe:2.3:a:gradle:gradle:*:*:*:*:enterprise:*:*:*")?.sw_edition).toBe(
      "enterprise",
    );
    expect(parseCpe("cpe:2.3:a:python:python:3.9.0:*:*:*:*:*:x64:*")?.target_hw).toBe("x64");
  });

  it("defaults missing trailing components to ANY", () => {
    // NVD always emits all 13 components, but a truncated string must not throw.
    expect(parseCpe("cpe:2.3:a:golang:go:1.21.0")).toMatchObject({
      update: "*",
      target_sw: "*",
      other: "*",
    });
  });
});

describe("isCpeExcluded", () => {
  const cpe = (s: string) => parseCpe(s)!;
  const enterprise = cpe("cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:enterprise:*:*");
  const cli = cpe("cpe:2.3:a:hashicorp:terraform:1.5.6:*:*:*:*:*:*:*");

  it("excludes a CPE whose component equals a rule's value", () => {
    expect(isCpeExcluded(enterprise, [{ target_sw: "enterprise" }])).toBe(true);
  });

  it("never excludes ANY or NA components", () => {
    expect(isCpeExcluded(cli, [{ target_sw: "enterprise" }])).toBe(false);
    // CVE-2023-4782 names the CLI with target_sw "-" (NA); it must keep matching.
    const na = cpe("cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:-:*:*");
    expect(isCpeExcluded(na, [{ target_sw: "enterprise" }])).toBe(false);
  });

  it("ORs rules and ANDs the components within one rule", () => {
    const aws = cpe("cpe:2.3:a:hashicorp:terraform:*:*:*:*:*:aws:*:*");
    const rules = [{ target_sw: "enterprise" }, { target_sw: "aws" }];
    expect(isCpeExcluded(aws, rules)).toBe(true);
    expect(isCpeExcluded(enterprise, rules)).toBe(true);
    // Both components must match within a single rule.
    expect(isCpeExcluded(enterprise, [{ target_sw: "enterprise", sw_edition: "x" }])).toBe(false);
  });

  it("compares case-insensitively", () => {
    expect(isCpeExcluded(enterprise, [{ target_sw: "Enterprise" }])).toBe(true);
  });

  it("excludes nothing with no rules, or with an empty rule", () => {
    expect(isCpeExcluded(enterprise, [])).toBe(false);
    expect(isCpeExcluded(enterprise, [{}])).toBe(false);
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
