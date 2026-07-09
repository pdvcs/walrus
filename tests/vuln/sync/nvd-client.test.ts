import { describe, expect, it, vi, beforeAll, afterEach, afterAll } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { readFileSync } from "fs";
import { join } from "path";
import { NvdClient, type NvdCvePage } from "../../../src/vuln/sync/nvd-client.js";

const noSleep = async (_ms: number) => {};

const FIXTURES = join(process.cwd(), "tests/fixtures/vuln");
const notepadPage = JSON.parse(
  readFileSync(join(FIXTURES, "nvd-cves-notepad.json"), "utf8"),
) as NvdCvePage;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function page(startIndex: number, total: number, count: number): NvdCvePage {
  return {
    startIndex,
    totalResults: total,
    resultsPerPage: count,
    vulnerabilities: Array.from({ length: count }, (_, i) => ({
      cve: { id: `CVE-2024-${startIndex + i}` },
    })),
  };
}

// ── Deterministic pagination / backoff (injected fetch, never touches network) ──

describe("NvdClient (injected fetch)", () => {
  it("assembles all pages via pagination", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(page(0, 4500, 2000)))
      .mockResolvedValueOnce(jsonResponse(page(2000, 4500, 2000)))
      .mockResolvedValueOnce(jsonResponse(page(4000, 4500, 500)));

    const client = new NvdClient({ apiKey: "k", fetchFn, backoffBaseMs: 1 }, noSleep);
    const items = await client.cvesForCpe("cpe:2.3:a:x:y");

    expect(items).toHaveLength(4500);
    expect(fetchFn).toHaveBeenCalledTimes(3);
    const secondUrl = String(fetchFn.mock.calls[1][0]);
    expect(secondUrl).toContain("startIndex=2000");
    expect(secondUrl).toContain("resultsPerPage=2000");
  });

  it("backs off on 503 then succeeds", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse({}, 503))
      .mockResolvedValueOnce(jsonResponse({}, 403))
      .mockResolvedValueOnce(jsonResponse(page(0, 1, 1)));

    const sleeps: number[] = [];
    const client = new NvdClient(
      { apiKey: "k", fetchFn, backoffBaseMs: 100 },
      async (ms) => void sleeps.push(ms),
    );
    const items = await client.cvesForCpe("cpe:2.3:a:x:y");

    expect(items).toHaveLength(1);
    expect(fetchFn).toHaveBeenCalledTimes(3);
    const backoffs = sleeps.filter((s) => s >= 100);
    expect(backoffs.length).toBe(2);
    expect(backoffs[1]).toBeGreaterThan(backoffs[0]);
  });

  it("gives up after maxRetries with a typed error", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse({}, 403));
    const client = new NvdClient(
      { apiKey: "k", fetchFn, backoffBaseMs: 1, maxRetries: 2 },
      noSleep,
    );
    await expect(client.cvesForCpe("cpe:2.3:a:x:y")).rejects.toThrow(/after 2 retries/);
    expect(fetchFn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it("does not retry on non-retryable status", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse({}, 404));
    const client = new NvdClient({ apiKey: "k", fetchFn, backoffBaseMs: 1 }, noSleep);
    await expect(client.cvesForCpe("cpe:2.3:a:x:y")).rejects.toThrow(/no retry for HTTP 404/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("rate limiter waits once the keyless window budget is used", async () => {
    vi.useFakeTimers();
    try {
      const fetchFn = vi
        .fn()
        .mockImplementation(() => Promise.resolve(jsonResponse(page(0, 1, 1))));
      const sleeps: number[] = [];
      const client = new NvdClient({ fetchFn, apiKey: undefined, backoffBaseMs: 1 }, async (ms) => {
        sleeps.push(ms);
        vi.setSystemTime(Date.now() + ms);
      });

      for (let i = 0; i < 5; i++) await client.cvesForCpe(`cpe:2.3:a:x:y${i}`);

      expect(sleeps.length).toBeGreaterThanOrEqual(1);
      expect(Math.max(...sleeps)).toBeGreaterThan(25_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it("sends the apiKey header when configured, omits it when keyless", async () => {
    const withKey = vi.fn().mockResolvedValue(jsonResponse(page(0, 1, 1)));
    await new NvdClient({ apiKey: "sekret", fetchFn: withKey }, noSleep).cvesForCpe(
      "cpe:2.3:a:x:y",
    );
    const h1 = (withKey.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(h1["apiKey"]).toBe("sekret");

    const keyless = vi.fn().mockResolvedValue(jsonResponse(page(0, 1, 1)));
    await new NvdClient({ apiKey: undefined, fetchFn: keyless }, noSleep).cvesForCpe(
      "cpe:2.3:a:x:y",
    );
    const h2 = (keyless.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(h2["apiKey"]).toBeUndefined();
  });
});

// ── msw-served fixture: proves the client works against real NVD URLs ──────────

describe("NvdClient (msw fixture)", () => {
  const server = setupServer();
  beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());

  it("fetches the recorded notepad page through the default global fetch", async () => {
    server.use(
      http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", () =>
        HttpResponse.json(notepadPage),
      ),
    );
    const client = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, noSleep);
    const items = await client.cvesForCpe("cpe:2.3:a:notepad-plus-plus:notepad\\+\\+");
    expect(items.length).toBe(notepadPage.vulnerabilities.length);
    expect(items[0].cve.id).toMatch(/^CVE-/);
  });
});
