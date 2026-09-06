import { describe, expect, it, vi, beforeAll, afterEach, afterAll } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { readFileSync } from "fs";
import { join } from "path";
import { NvdClient, type NvdCveItem, type NvdCvePage } from "../../../src/vuln/sync/nvd-client.js";

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

const timeoutError = (): DOMException =>
  new DOMException("The operation was aborted due to timeout", "TimeoutError");

/**
 * A 200 whose body fails partway through the stream.
 *
 * `jsonResponse` above cannot express this: its body is an already-materialized string, so
 * `res.json()` on one can never reject. That is precisely why no test caught WAL-111 — the whole
 * suite was structurally incapable of failing a body read, and the timeout test that existed
 * rejected the *fetch promise* instead, which is the one phase that was always handled.
 */
function streamingFailure(err: unknown, status = 200): Response {
  const stream = new ReadableStream({
    start(controller) {
      // A partial, unparseable prefix: the shape a real aborted page arrives in.
      controller.enqueue(new TextEncoder().encode('{"resultsPerPage":2000,"vulnerab'));
      controller.error(err);
    },
  });
  return new Response(stream, { status, headers: { "content-type": "application/json" } });
}

/**
 * Drain `cvePages` into one array.
 *
 * This is what `NvdClient.cvesForCpe` used to be, moved into the test that needs it (WAL-97).
 * The client itself must not offer an accumulating helper — two production callers reached for
 * one and each became an out-of-memory abort (WAL-95, WAL-97) — but the pagination, retry and
 * rate-limit behaviour below is most readable stated over a finished list, and here the pages
 * come from a fake transport with a handful of rows in them. Accumulation is not the defect;
 * accumulation reachable from `src/` is, and `tests/infra/accumulating-helpers.test.ts` is what
 * keeps it out.
 */
async function collect(
  client: NvdClient,
  virtualMatchString: string,
  extra: Record<string, string> = {},
): Promise<NvdCveItem[]> {
  const items: NvdCveItem[] = [];
  for await (const p of client.cvePages({ virtualMatchString, ...extra })) {
    items.push(...p.vulnerabilities);
  }
  return items;
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
    const items = await collect(client, "cpe:2.3:a:x:y");

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
    const items = await collect(client, "cpe:2.3:a:x:y");

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
    await expect(collect(client, "cpe:2.3:a:x:y")).rejects.toThrow(/after 2 retries/);
    expect(fetchFn).toHaveBeenCalledTimes(3); // initial + 2 retries
  });

  it("does not retry on non-retryable status", async () => {
    const fetchFn = vi.fn().mockResolvedValue(jsonResponse({}, 404));
    const client = new NvdClient({ apiKey: "k", fetchFn, backoffBaseMs: 1 }, noSleep);
    await expect(collect(client, "cpe:2.3:a:x:y")).rejects.toThrow(/no retry for HTTP 404/);
    expect(fetchFn).toHaveBeenCalledTimes(1);
  });

  it("supplies an abort timeout and retries timed-out requests", async () => {
    const timeout = Object.assign(new Error("timed out"), { name: "TimeoutError" });
    const fetchFn = vi.fn().mockRejectedValue(timeout);
    const client = new NvdClient(
      { apiKey: "k", fetchFn, backoffBaseMs: 1, maxRetries: 2, requestTimeoutMs: 25 },
      noSleep,
    );

    await expect(collect(client, "cpe:2.3:a:x:y")).rejects.toThrow(/after 2 retries/);
    expect(fetchFn).toHaveBeenCalledTimes(3);
    for (const call of fetchFn.mock.calls) {
      expect((call[1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
    }
  });

  // ── Body-phase transport failures (WAL-111) ─────────────────────────────────
  //
  // `AbortSignal.timeout` bounds the entire exchange, not just the handshake. NVD answers a
  // 2000-row page quickly and then streams it, so the deadline lands during the body read far
  // more often than during the handshake — that is the failure that reached production on 2 and
  // 4 September 2026, five times in the preceding week. The test above covers the handshake and
  // passed throughout.

  it("retries a timeout that lands during the body read", async () => {
    const fetchFn = vi
      .fn()
      .mockResolvedValueOnce(streamingFailure(timeoutError()))
      .mockResolvedValueOnce(jsonResponse(page(0, 1, 1)));

    const client = new NvdClient({ apiKey: "k", fetchFn, backoffBaseMs: 1 }, noSleep);
    const items = await collect(client, "cpe:2.3:a:x:y");

    expect(items).toHaveLength(1);
    expect(fetchFn).toHaveBeenCalledTimes(2);
  });

  it.each([
    ["the fetch promise rejects", () => Promise.reject(timeoutError())],
    ["the body stream aborts mid-read", () => Promise.resolve(streamingFailure(timeoutError()))],
    [
      "the body is truncated JSON",
      () =>
        Promise.resolve(
          new Response('{"resultsPer', {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
        ),
    ],
  ])("wraps a persistent failure rather than leaking it when %s", async (_case, respond) => {
    const fetchFn = vi.fn().mockImplementation(respond);
    const client = new NvdClient(
      { apiKey: "k", fetchFn, backoffBaseMs: 1, maxRetries: 2 },
      noSleep,
    );

    const err: unknown = await collect(client, "cpe:2.3:a:x:y").then(
      () => {
        throw new Error("expected the walk to reject");
      },
      (e: unknown) => e,
    );

    // The invariant, stated once for every stage a request can fail at: nothing leaves `get`
    // except a wrapped Error naming the retry budget. A bare DOMException escaping here is the
    // exact production signature — Cloud Logging carried `TimeoutError: The operation was
    // aborted due to timeout` instead of this message, which is how we knew the retry loop had
    // been bypassed rather than exhausted.
    expect((err as Error).name).toBe("Error");
    expect((err as Error).message).toMatch(/NVD request failed after 2 retries/);
    expect(fetchFn).toHaveBeenCalledTimes(3);
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

      for (let i = 0; i < 5; i++) await collect(client, `cpe:2.3:a:x:y${i}`);

      expect(sleeps.length).toBeGreaterThanOrEqual(1);
      expect(Math.max(...sleeps)).toBeGreaterThan(25_000);
    } finally {
      vi.useRealTimers();
    }
  });

  it("sends the apiKey header when configured, omits it when keyless", async () => {
    const withKey = vi.fn().mockResolvedValue(jsonResponse(page(0, 1, 1)));
    await collect(new NvdClient({ apiKey: "sekret", fetchFn: withKey }, noSleep), "cpe:2.3:a:x:y");
    const h1 = (withKey.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
    expect(h1["apiKey"]).toBe("sekret");

    const keyless = vi.fn().mockResolvedValue(jsonResponse(page(0, 1, 1)));
    await collect(new NvdClient({ apiKey: undefined, fetchFn: keyless }, noSleep), "cpe:2.3:a:x:y");
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
    const items = await collect(client, "cpe:2.3:a:notepad-plus-plus:notepad\\+\\+");
    expect(items.length).toBe(notepadPage.vulnerabilities.length);
    expect(items[0].cve.id).toMatch(/^CVE-/);
  });
});
