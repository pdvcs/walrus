import { describe, it, expect, vi, afterEach } from "vitest";
import { resolveLatestVersion } from "../../src/services/latest-version.js";
import { LatestVersionSchema } from "../../src/types/watch-config.js";
import { config as appConfig } from "../../src/config/index.js";

function stubJson(body: unknown, status = 200) {
  const fn = vi.fn(async () => new Response(JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => vi.unstubAllGlobals());

const PYPI = {
  type: "json" as const,
  url: "https://pypi.org/pypi/requests/json",
  version_path: "$.info.version",
};

describe("resolveLatestVersion — json (WAL-54)", () => {
  it("reads the version at the JSONPath", async () => {
    stubJson({ info: { version: "2.34.0" }, releases: {} });
    expect(await resolveLatestVersion(PYPI)).toBe("2.34.0");
  });

  it("accepts a numeric value", async () => {
    stubJson({ info: { version: 3 } });
    expect(await resolveLatestVersion(PYPI)).toBe("3");
  });

  it("applies tag_pattern to the extracted value", async () => {
    stubJson({ info: { version: "release-2.34.0" } });
    expect(await resolveLatestVersion({ ...PYPI, tag_pattern: "^release-(.+)$" })).toBe("2.34.0");
  });

  it("fails clearly when the path finds nothing", async () => {
    stubJson({ other: 1 });
    await expect(resolveLatestVersion(PYPI)).rejects.toThrow(/found no string or number/);
  });

  it("fails when tag_pattern does not match", async () => {
    stubJson({ info: { version: "2.34.0" } });
    await expect(resolveLatestVersion({ ...PYPI, tag_pattern: "^v(.+)$" })).rejects.toThrow(
      /did not match/,
    );
  });

  it("refuses a value that is plainly not a version", async () => {
    stubJson({ info: { version: "no digits here" } });
    await expect(resolveLatestVersion(PYPI)).rejects.toThrow(/does not look like a version/);
    stubJson({ info: { version: "1.0 ".repeat(40) } });
    await expect(resolveLatestVersion(PYPI)).rejects.toThrow(/does not look like a version/);
  });

  it("surfaces an upstream HTTP failure", async () => {
    stubJson({ message: "gone" }, 404);
    await expect(resolveLatestVersion(PYPI)).rejects.toThrow();
  });
});

describe("resolveLatestVersion — github-release (WAL-54)", () => {
  const original = appConfig.GITHUB_TOKEN;
  afterEach(() => {
    appConfig.GITHUB_TOKEN = original;
  });
  const GH = { type: "github-release" as const, repo: "hashicorp/terraform" };

  it("asks for the repo's latest release and strips the conventional v", async () => {
    const fn = stubJson({ tag_name: "v1.14.2" });
    expect(await resolveLatestVersion(GH)).toBe("1.14.2");
    expect((fn.mock.calls[0] as unknown[])[0]).toBe(
      "https://api.github.com/repos/hashicorp/terraform/releases/latest",
    );
  });

  it("honours an explicit tag_pattern instead of stripping v", async () => {
    stubJson({ tag_name: "jq-1.8.1" });
    expect(await resolveLatestVersion({ ...GH, tag_pattern: "^jq-(.+)$" })).toBe("1.8.1");
  });

  it("sends the bearer token when configured, and none when not", async () => {
    appConfig.GITHUB_TOKEN = "ghp_example";
    let fn = stubJson({ tag_name: "v1.0.0" });
    await resolveLatestVersion(GH);
    const headers = (): Record<string, string> =>
      (fn.mock.calls[0] as unknown as [string, RequestInit])[1].headers as Record<string, string>;
    expect(headers()["Authorization"]).toBe("Bearer ghp_example");

    appConfig.GITHUB_TOKEN = undefined;
    fn = stubJson({ tag_name: "v1.0.0" });
    await resolveLatestVersion(GH);
    expect(headers()).not.toHaveProperty("Authorization");
  });

  it("fails when the repo has no release tag", async () => {
    stubJson({});
    await expect(resolveLatestVersion(GH)).rejects.toThrow(/no latest release/);
  });
});

describe("LatestVersionSchema", () => {
  it("rejects unknown keys and a tag_pattern without exactly one capture group", () => {
    expect(LatestVersionSchema.safeParse({ ...PYPI, extra: 1 }).success).toBe(false);
    expect(LatestVersionSchema.safeParse({ ...PYPI, tag_pattern: "^v.+$" }).success).toBe(false);
    expect(LatestVersionSchema.safeParse({ ...PYPI, tag_pattern: "^(v)(.+)$" }).success).toBe(
      false,
    );
    expect(LatestVersionSchema.safeParse({ ...PYPI, tag_pattern: "(" }).success).toBe(false);
    expect(LatestVersionSchema.safeParse({ ...PYPI, tag_pattern: "^v(.+)$" }).success).toBe(true);
  });

  it("requires owner/name for a github repo", () => {
    expect(LatestVersionSchema.safeParse({ type: "github-release", repo: "nope" }).success).toBe(
      false,
    );
    expect(
      LatestVersionSchema.safeParse({ type: "github-release", repo: "psf/requests" }).success,
    ).toBe(true);
  });
});
