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
