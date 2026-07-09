import { describe, expect, it } from "vitest";
import { nameVariants, normalizeName } from "../../src/vuln/normalize.js";

describe("normalizeName", () => {
  it("lowercases, trims, and collapses whitespace", () => {
    expect(normalizeName("  NOTEPAD  plus PLUS ")).toBe("notepad plus plus");
  });

  it("treats underscores as spaces", () => {
    expect(normalizeName("intellij_idea")).toBe("intellij idea");
  });

  it("leaves short names alone", () => {
    expect(normalizeName("npp")).toBe("npp");
    expect(normalizeName("rg")).toBe("rg");
  });
});

describe("nameVariants", () => {
  it("expands ++ into plus variants while keeping the raw form", () => {
    const v = nameVariants("Notepad++");
    expect(v).toContain("notepad++");
    expect(v).toContain("notepad plus plus");
    expect(v).toContain("notepadplusplus");
  });

  it("expands dots (node.js → nodejs, node js)", () => {
    const v = nameVariants("Node.js");
    expect(v).toContain("node.js");
    expect(v).toContain("nodejs");
    expect(v).toContain("node js");
  });

  it("squashes multi-word names", () => {
    const v = nameVariants("visual studio code");
    expect(v).toContain("visualstudiocode");
  });

  it("produces identical variant sets for messy versions of the same name", () => {
    const a = new Set(nameVariants("  NOTEPAD++ "));
    const b = new Set(nameVariants("notepad++"));
    expect(a).toEqual(b);
  });
});
