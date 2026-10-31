import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createEgressFetch,
  fetchJsonWithRetry,
  fetchWithRetry,
  HttpRequestError,
} from "../../src/common/http.js";
import { configureEgress } from "../../src/common/egress-rules.js";
import { log } from "../../src/common/log.js";

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  // Every createEgressFetch() call reads the shared module-level state, so a rule/mode left
  // behind by one test would otherwise leak into the next (WAL-113).
  configureEgress({ mode: "direct", rules: [] });
});

describe("createEgressFetch", () => {
  it("passes calls straight through to the global fetch when no rule matches (WAL-112/113: no behaviour change)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    const init = { method: "GET" };
    await egressFetch("https://example.test/artifact", init);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith("https://example.test/artifact", init);
  });

  it("resolves the global fetch at call time, not at creation time", async () => {
    // The chokepoint is created once (module load, or a service constructor) but must still
    // honour a fetch stub installed afterwards — this is what keeps every existing test's
    // `vi.stubGlobal("fetch", ...)` working unchanged after migrating a call site onto it.
    const egressFetch = createEgressFetch({ purpose: "artifact" });
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);

    await egressFetch("https://example.test/artifact");

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("rewrites the URL and merges headers when a rule matches (WAL-113)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({
      mode: "rules",
      rules: [
        {
          match: "https://github.com/",
          rewrite: "https://artifactory.corp/artifactory/github-remote/",
          headers: { Authorization: "Bearer secret-token" },
        },
      ],
    });

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    await egressFetch("https://github.com/foo/bar/releases/x.tar.gz", {
      headers: { Accept: "application/octet-stream" },
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, calledInit] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toBe(
      "https://artifactory.corp/artifactory/github-remote/foo/bar/releases/x.tar.gz",
    );
    const headers = new Headers(calledInit.headers);
    expect(headers.get("authorization")).toBe("Bearer secret-token");
    expect(headers.get("accept")).toBe("application/octet-stream");
  });

  it("implements the simplest catch-all wrap with no special-casing (WAL-113 AC3)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({
      mode: "rules",
      rules: [{ match: "https://", rewrite: "https://my-rewriting-proxy/url/https://" }],
    });

    const egressFetch = createEgressFetch({ purpose: "discovery" });
    await egressFetch("https://example.test/some/path?x=1");

    expect(fetchMock).toHaveBeenCalledWith(
      "https://my-rewriting-proxy/url/https://example.test/some/path?x=1",
      expect.anything(),
    );
  });

  it("prefers the longest matching prefix regardless of file order (WAL-113 AC2)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({
      mode: "rules",
      rules: [
        // Catch-all listed first; the more specific rule must still win.
        { match: "https://", rewrite: "https://catch-all.corp/" },
        { match: "https://github.com/", rewrite: "https://specific.corp/" },
      ],
    });

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    await egressFetch("https://github.com/foo");

    expect(fetchMock).toHaveBeenCalledWith("https://specific.corp/foo", expect.anything());
  });

  it("restricts a rule to its declared purpose (WAL-113 AC5)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({
      mode: "rules",
      rules: [
        {
          match: "https://services.nvd.nist.gov/",
          purpose: "vuln-feed",
          rewrite: "https://egress.corp/nvd/",
        },
      ],
    });

    const vulnFeedFetch = createEgressFetch({ purpose: "vuln-feed" });
    await vulnFeedFetch("https://services.nvd.nist.gov/rest/json/cves/2.0");
    expect(fetchMock).toHaveBeenLastCalledWith(
      "https://egress.corp/nvd/rest/json/cves/2.0",
      expect.anything(),
    );

    const artifactFetch = createEgressFetch({ purpose: "artifact" });
    await artifactFetch("https://services.nvd.nist.gov/rest/json/cves/2.0");
    expect(fetchMock).toHaveBeenLastCalledWith(
      "https://services.nvd.nist.gov/rest/json/cves/2.0",
      undefined,
    );
  });

  it("mode=direct proceeds silently when nothing matches (WAL-113 AC6)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    const warnSpy = vi.spyOn(log, "warn");
    configureEgress({ mode: "direct", rules: [] });

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    await egressFetch("https://example.test/unmatched");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("mode=rules warns and proceeds direct when nothing matches (WAL-113 AC7)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    const warnSpy = vi.spyOn(log, "warn");
    configureEgress({ mode: "rules", rules: [] });

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    const response = await egressFetch("https://example.test/unmatched");

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect((response as { ok: boolean }).ok).toBe(true);
  });

  it("mode=strict refuses an unmatched request without ever calling fetch (WAL-113 AC8)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({ mode: "strict", rules: [] });

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    await expect(egressFetch("https://example.test/unmatched")).rejects.toThrow(HttpRequestError);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("strict still applies a matching rule rather than refusing it", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, status: 200 });
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({
      mode: "strict",
      rules: [{ match: "https://example.test/", rewrite: "https://proxy.corp/" }],
    });

    const egressFetch = createEgressFetch({ purpose: "artifact" });
    await egressFetch("https://example.test/artifact.zip");

    expect(fetchMock).toHaveBeenCalledWith("https://proxy.corp/artifact.zip", expect.anything());
  });
});

describe("fetchWithRetry via the egress chokepoint", () => {
  it("still honours a global fetch stub after routing through createEgressFetch (WAL-112)", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ ok: true }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const response = await fetchWithRetry("https://example.test/discovery");

    expect(response.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("a strict-mode refusal is not retried (WAL-113: HttpRequestError already classified)", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    configureEgress({ mode: "strict", rules: [] });

    await expect(
      fetchWithRetry("https://example.test/discovery", {}, { maxRetries: 2, retryBaseDelayMs: 0 }),
    ).rejects.toThrow("Egress refused");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("normalizeFetchError via fetchWithRetry", () => {
  it("surfaces err.cause instead of the opaque 'fetch failed' message (WAL-116)", async () => {
    const cause = Object.assign(new Error("ENOTFOUND example.test"), { code: "ENOTFOUND" });
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("fetch failed", { cause }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      fetchWithRetry("https://example.test/discovery", {}, { maxRetries: 0 }),
    ).rejects.toThrow(/fetch failed: ENOTFOUND example\.test/);
  });

  it("leaves a plain error message alone when there is no cause", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError("fetch failed"));
    vi.stubGlobal("fetch", fetchMock);

    let thrown: unknown;
    try {
      await fetchWithRetry("https://example.test/discovery", {}, { maxRetries: 0 });
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(HttpRequestError);
    expect((thrown as Error).message).toBe("fetch failed");
  });
});

describe("http retry helpers", () => {
  it("retries retryable status codes and succeeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        status: 500,
        text: () => Promise.resolve("upstream error"),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ ok: true }),
      });

    vi.stubGlobal("fetch", fetchMock);

    const response = await fetchWithRetry(
      "https://example.test/releases",
      {},
      { maxRetries: 1, retryBaseDelayMs: 0 },
    );

    expect(response.ok).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("throws timeout error when request exceeds timeout", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((_url: string, init?: RequestInit) => {
        return new Promise((_, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("Aborted", "AbortError"));
          });
        });
      }),
    );

    await expect(
      fetchWithRetry("https://example.test/slow", {}, { timeoutMs: 5, maxRetries: 0 }),
    ).rejects.toThrow(HttpRequestError);

    await expect(
      fetchWithRetry("https://example.test/slow", {}, { timeoutMs: 5, maxRetries: 0 }),
    ).rejects.toThrow("timed out");
  });

  it("parses JSON payload", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ releases: ["1.2.3"] }),
      }),
    );

    const payload = await fetchJsonWithRetry<{ releases: string[] }>(
      "https://example.test/releases",
      {},
      { maxRetries: 0 },
    );

    expect(payload.releases).toEqual(["1.2.3"]);
  });
});

/**
 * WAL-103. A spent quota is not the same failure as a broken upstream, and it reads very
 * differently to whoever an alert wakes. It must also not be retried: the backoff here is
 * seconds while a rate-limit window is minutes to an hour, so every retry is guaranteed to fail
 * and spends quota the next package's discovery needs. GitHub answers 403 for this, not 429,
 * so the status alone cannot tell it apart from a permissions failure.
 */
describe("upstream rate limiting", () => {
  function rateLimitedResponse(status: number, remaining: string, reset?: string) {
    // `?? null` rather than letting an absent `reset` come back as `undefined`: the real
    // `Headers.get` returns `string | null`, and a stub that answers `undefined` invites the
    // production code to be written against a shape no browser or Node runtime produces.
    const headers: Record<string, string | undefined> = {
      "x-ratelimit-remaining": remaining,
      "x-ratelimit-reset": reset,
    };
    return {
      ok: false,
      status,
      headers: { get: (name: string) => headers[name] ?? null },
      text: () => Promise.resolve('{"message":"API rate limit exceeded for 1.2.3.4."}'),
    };
  }

  it("fails immediately on a rate-limited 403 rather than retrying", async () => {
    const fetchMock = vi.fn().mockResolvedValue(rateLimitedResponse(403, "0"));
    vi.stubGlobal("fetch", fetchMock);

    await expect(fetchWithRetry("https://api.github.test/x")).rejects.toThrow(HttpRequestError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("flags the error as rate limited and names the reset time", async () => {
    // 2026-09-01T00:00:00Z
    const reset = String(Math.floor(Date.UTC(2026, 8, 1) / 1000));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(rateLimitedResponse(403, "0", reset)));

    const err = await fetchWithRetry("https://api.github.test/x").catch((e: unknown) => e);

    expect(err).toBeInstanceOf(HttpRequestError);
    expect((err as HttpRequestError).rateLimited).toBe(true);
    expect((err as HttpRequestError).status).toBe(403);
    expect((err as Error).message).toContain("2026-09-01T00:00:00.000Z");
  });

  it("does not mistake a plain 403 for a rate limit", async () => {
    // A permissions failure has quota left; it must stay a generic non-retryable failure.
    const fetchMock = vi.fn().mockResolvedValue(rateLimitedResponse(403, "57"));
    vi.stubGlobal("fetch", fetchMock);

    const err = await fetchWithRetry("https://api.github.test/x").catch((e: unknown) => e);

    expect((err as HttpRequestError).rateLimited).toBe(false);
  });

  it("still retries a 429 that has quota remaining", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(rateLimitedResponse(429, "5"))
      .mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) });
    vi.stubGlobal("fetch", fetchMock);

    await fetchJsonWithRetry("https://api.github.test/x", {}, { retryBaseDelayMs: 0 });

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

/**
 * The classification above is only useful if it survives being thrown. It did not: the throw
 * inside the try block was caught by the same function's catch and re-wrapped into a bare
 * HttpRequestError, dropping `status` and `rateLimited`. `json-api.ts` treats a 404 release feed
 * as "no releases yet" by testing `err.status === 404` — a branch that could never be reached.
 */
describe("error classification survives the retry loop", () => {
  it("preserves the status on a non-retryable HTTP failure", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        headers: { get: () => null },
        text: () => Promise.resolve("not found"),
      }),
    );

    const err = await fetchWithRetry("https://example.test/feed").catch((e: unknown) => e);

    expect(err).toBeInstanceOf(HttpRequestError);
    expect((err as HttpRequestError).status).toBe(404);
  });

  it("preserves the status after retries are exhausted", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 503,
        headers: { get: () => null },
        text: () => Promise.resolve("unavailable"),
      }),
    );

    const err = await fetchWithRetry(
      "https://example.test/feed",
      {},
      { maxRetries: 1, retryBaseDelayMs: 0 },
    ).catch((e: unknown) => e);

    expect((err as HttpRequestError).status).toBe(503);
  });
});
