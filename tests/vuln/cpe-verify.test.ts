import { describe, expect, it } from "vitest";
import { verifyCpePairs } from "../../src/vuln/cpe-verify.js";
import type { NvdClient } from "../../src/vuln/sync/nvd-client.js";

/** Fake NVD client exposing only what the probe uses. */
function fakeNvd(
  impl: (matchString: string) => Promise<unknown>,
): Pick<NvdClient, "cpeDictionary"> {
  return { cpeDictionary: impl };
}

describe("verifyCpePairs", () => {
  it("verifies a pair present in the dictionary", async () => {
    const nvd = fakeNvd(async () => ({ totalResults: 42 }));
    const res = await verifyCpePairs(nvd, ["oracle:openjdk"]);

    expect(res.verified).toBe(1);
    expect(res.results[0]).toMatchObject({
      pair: "oracle:openjdk",
      status: "verified",
      hits: 42,
    });
  });

  it("builds a proper match string from vendor:product", async () => {
    const seen: string[] = [];
    const nvd = fakeNvd(async (m) => {
      seen.push(m);
      return { totalResults: 1 };
    });
    await verifyCpePairs(nvd, ["some vendor:prod/uct"]);
    // CPE-formatted components get escaped; part is "a" for applications.
    expect(seen[0]).toContain("cpe:2.3:a:some\\ vendor:prod\\/uct");
  });

  it("reports zero-hit pairs as unverifiable without failing anything", async () => {
    const nvd = fakeNvd(async () => ({ totalResults: 0 }));
    const res = await verifyCpePairs(nvd, ["acme:mytool"]);

    expect(res.unverifiable).toBe(1);
    expect(res.verified).toBe(0);
    const verdict = res.results[0];
    expect(verdict.status).toBe("unverifiable");
    expect(verdict.hits).toBe(0);
    // The wording must not imply the pair is wrong — obscure products are legitimate.
    expect(verdict.detail).toMatch(/double-check/i);
    expect(verdict.detail).toMatch(/legitimately/i);
  });

  it("treats a lookup failure as unchecked and keeps probing other pairs", async () => {
    let calls = 0;
    const nvd = fakeNvd(async (matchString) => {
      calls++;
      if (matchString.includes("broken")) throw new Error("HTTP 503");
      return { totalResults: 3 };
    });
    const res = await verifyCpePairs(nvd, ["broken:pair", "good:pair"]);

    expect(calls).toBe(2);
    expect(res.unchecked).toBe(1);
    expect(res.verified).toBe(1);
    expect(res.results[0].status).toBe("unchecked");
    expect(res.results[0].detail).toMatch(/503/);
  });

  it("summarizes mixed outcomes across several pairs", async () => {
    const nvd = fakeNvd(async (m) =>
      m.includes("unknown") ? { totalResults: 0 } : { totalResults: 7 },
    );
    const res = await verifyCpePairs(nvd, ["a:b", "unknown:pair", "c:d"]);
    expect(res.verified).toBe(2);
    expect(res.unverifiable).toBe(1);
    expect(res.unchecked).toBe(0);
    expect(res.results).toHaveLength(3);
  });

  it("handles a missing totalResults defensively as unverifiable-with-null-hits", async () => {
    const nvd = fakeNvd(async () => ({}));
    const res = await verifyCpePairs(nvd, ["weird:response"]);
    expect(res.results[0].hits).toBeNull();
    expect(res.results[0].status).toBe("unverifiable");
  });
});
