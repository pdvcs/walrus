import { beforeEach, describe, expect, it, vi } from "vitest";
import { fetchJsonWithRetry, fetchWithRetry, HttpRequestError } from "../../src/common/http.js";

beforeEach(() => {
  vi.restoreAllMocks();
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
