import { describe, expect, it, afterEach } from "vitest";
import {
  parseBaseUrl,
  parseSince,
  parseSources,
  resolveToken,
  summarise,
} from "../../scripts/vuln-ingest-all.js";

describe("vuln-ingest-all — parseSince", () => {
  it("returns undefined when the flag is absent", () => {
    expect(parseSince([])).toBeUndefined();
    expect(parseSince(["--no-wait"])).toBeUndefined();
  });

  it("accepts a YYYY-MM-DD value", () => {
    expect(parseSince(["--since", "2015-01-01"])).toBe("2015-01-01");
  });

  it("rejects a malformed date before any request is made", () => {
    expect(() => parseSince(["--since", "2015"])).toThrow(/YYYY-MM-DD/);
    expect(() => parseSince(["--since", "last-tuesday"])).toThrow(/YYYY-MM-DD/);
  });

  it("rejects a missing value rather than swallowing the next flag", () => {
    expect(() => parseSince(["--since", "--no-wait"])).toThrow(/requires a value/);
    expect(() => parseSince(["--since"])).toThrow(/requires a value/);
  });
});

describe("vuln-ingest-all — parseBaseUrl", () => {
  const original = process.env.WALRUS_BASE_URL;
  afterEach(() => {
    if (original === undefined) delete process.env.WALRUS_BASE_URL;
    else process.env.WALRUS_BASE_URL = original;
  });

  it("defaults to local dev", () => {
    delete process.env.WALRUS_BASE_URL;
    expect(parseBaseUrl([])).toBe("http://localhost:8080");
  });

  it("strips trailing slashes so paths do not double up", () => {
    expect(parseBaseUrl(["--base-url", "https://walrus.example.com/"])).toBe(
      "https://walrus.example.com",
    );
    expect(parseBaseUrl(["--base-url", "https://walrus.example.com///"])).toBe(
      "https://walrus.example.com",
    );
  });

  it("prefers the flag over the environment", () => {
    process.env.WALRUS_BASE_URL = "https://from-env.example.com";
    expect(parseBaseUrl(["--base-url", "https://from-flag.example.com"])).toBe(
      "https://from-flag.example.com",
    );
    expect(parseBaseUrl([])).toBe("https://from-env.example.com");
  });
});

describe("vuln-ingest-all — parseSources", () => {
  it("defaults to every source", () => {
    expect(parseSources([])).toEqual(["nvd", "osv", "kev"]);
  });

  it("returns canonical order regardless of how they were typed", () => {
    // nvd first matters: it is the long-running job, and the others should not wait behind it
    // being typed last.
    expect(parseSources(["--sources", "kev,nvd"])).toEqual(["nvd", "kev"]);
  });

  it("de-duplicates and tolerates whitespace and case", () => {
    expect(parseSources(["--sources", " OSV , osv ,NVD"])).toEqual(["nvd", "osv"]);
  });

  it("names the unknown source rather than silently ignoring it", () => {
    expect(() => parseSources(["--sources", "nvd,ghsa"])).toThrow(/ghsa/);
  });

  it("rejects an empty list", () => {
    expect(() => parseSources(["--sources", ","])).toThrow(/at least one source/);
  });
});

describe("vuln-ingest-all — summarise", () => {
  it("flattens the nested summary the sync endpoints actually return", () => {
    // Real /admin/v1/vuln-sync/osv shape: the counts worth printing are one level down, and a
    // top-level-only walk reports a successful sync with no figures at all.
    expect(
      summarise({
        source: "osv",
        ok: true,
        summary: { packages: 14, vulns: 421, affectsUpserted: 1140, failures: 0 },
      }),
    ).toBe("packages=14 vulns=421 affectsUpserted=1140 failures=0");
  });

  it("keeps top-level scalars and drops ok/source", () => {
    expect(summarise({ source: "kev", ok: true, flagged: 5, cleared: 0 })).toBe(
      "flagged=5 cleared=0",
    );
  });

  it("returns an empty string when there is nothing to report", () => {
    expect(summarise({ source: "kev", ok: true })).toBe("");
  });

  it("does not render null or nested-nested objects as values", () => {
    expect(summarise({ ok: true, skipped: null, summary: { n: 1, inner: { deep: 2 } } })).toBe(
      "n=1",
    );
  });
});

describe("vuln-ingest-all — resolveToken", () => {
  const original = process.env.WALRUS_API_TOKEN;
  afterEach(() => {
    if (original === undefined) delete process.env.WALRUS_API_TOKEN;
    else process.env.WALRUS_API_TOKEN = original;
  });

  it("reads the environment", () => {
    process.env.WALRUS_API_TOKEN = "env-token";
    expect(resolveToken([])).toBe("env-token");
  });

  it("prefers the flag over the environment", () => {
    process.env.WALRUS_API_TOKEN = "env-token";
    expect(resolveToken(["--token", "flag-token"])).toBe("flag-token");
  });

  it("explains where to get a token when none is set", () => {
    delete process.env.WALRUS_API_TOKEN;
    expect(() => resolveToken([])).toThrow(/\/admin\/v1\/tokens/);
  });
});
