/**
 * NVD API 2.0 client (ported from vulncheck `worker/nvdClient.ts`).
 * Pagination (2,000/page), sliding-window rate limiting (5 req/30s keyless,
 * 50 with an API key), exponential backoff on 403/429/503/5xx, and
 * lastModStartDate/lastModEndDate windows for incremental sync.
 */
import { config } from "../../config/index.js";

const BASE_CVES = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const BASE_CPES = "https://services.nvd.nist.gov/rest/json/cpes/2.0";

export interface NvdCveItem {
  cve: {
    id: string;
    published?: string;
    lastModified?: string;
    descriptions?: Array<{ lang: string; value: string }>;
    metrics?: Record<
      string,
      Array<{
        type?: string;
        cvssData?: { baseScore?: number; vectorString?: string; baseSeverity?: string };
        baseSeverity?: string;
      }>
    >;
    configurations?: Array<{
      operator?: string;
      negate?: boolean;
      nodes: Array<{
        operator?: string;
        negate?: boolean;
        cpeMatch?: Array<{
          criteria: string;
          vulnerable: boolean;
          versionStartIncluding?: string;
          versionStartExcluding?: string;
          versionEndIncluding?: string;
          versionEndExcluding?: string;
        }>;
      }>;
    }>;
    references?: Array<{ url: string }>;
  };
}

export interface NvdCvePage {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: NvdCveItem[];
}

export interface NvdClientOptions {
  apiKey?: string;
  fetchFn?: typeof fetch;
  /** Base delay in ms for exponential backoff (tests shrink this). */
  backoffBaseMs?: number;
  maxRetries?: number;
  requestTimeoutMs?: number;
  logger?: { info: (msg: string) => void; warn: (msg: string) => void };
}

/**
 * Sliding-window rate limiter: NVD allows 5 requests / 30s without a key,
 * 50 / 30s with one. We stay one under the published budget to be safe.
 */
class RateLimiter {
  private timestamps: number[] = [];
  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly sleepFn: (ms: number) => Promise<void>,
  ) {}

  async acquire(): Promise<void> {
    for (;;) {
      const now = Date.now();
      this.timestamps = this.timestamps.filter((t) => now - t < this.windowMs);
      if (this.timestamps.length < this.limit) {
        this.timestamps.push(now);
        return;
      }
      const oldest = this.timestamps[0];
      await this.sleepFn(oldest + this.windowMs - now + 50);
    }
  }
}

/**
 * Render an unknown throwable for a message.
 *
 * Not `String(err)`: the WAL-111 timeouts reached Cloud Logging as a DOMException serialized
 * with every one of its legacy constants (`ABORT_ERR=20;DATA_CLONE_ERR=25;…`), burying the one
 * line that mattered. Name and message are what a reader needs, and the retry wrapper is where
 * they end up.
 */
function describeError(err: unknown): string {
  if (err instanceof Error) return `${err.name}: ${err.message}`;
  if (typeof err === "string") return err;
  return JSON.stringify(err) ?? "unknown error";
}

export class NvdClient {
  private readonly apiKey: string | undefined;
  private readonly fetchFn: typeof fetch;
  private readonly backoffBaseMs: number;
  private readonly maxRetries: number;
  private readonly requestTimeoutMs: number;
  private readonly limiter: RateLimiter;
  private readonly log: NonNullable<NvdClientOptions["logger"]>;
  private readonly sleepFn: (ms: number) => Promise<void>;

  constructor(opts: NvdClientOptions = {}, sleepFn?: (ms: number) => Promise<void>) {
    // Respect an explicitly passed `apiKey: undefined` (forces keyless mode);
    // only fall back to the env key when the option is absent entirely.
    this.apiKey = Object.hasOwn(opts, "apiKey") ? opts.apiKey : config.NVD_API_KEY;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.backoffBaseMs = opts.backoffBaseMs ?? 2000;
    this.maxRetries = opts.maxRetries ?? 5;
    this.requestTimeoutMs = opts.requestTimeoutMs ?? config.VULN_HTTP_TIMEOUT_MS;
    this.log = opts.logger ?? { info: () => {}, warn: () => {} };
    this.sleepFn = sleepFn ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.limiter = new RateLimiter(this.apiKey ? 45 : 4, 30_000, this.sleepFn);
  }

  /** One rate-limited, retried GET returning parsed JSON. */
  private async get(url: string): Promise<unknown> {
    let attempt = 0;
    for (;;) {
      await this.limiter.acquire();
      const headers: Record<string, string> = {};
      if (this.apiKey) headers["apiKey"] = this.apiKey;

      let res: Response | undefined;
      // Widened from `networkErr` (WAL-111): this now holds a body-phase failure too, which is
      // not a network error in the usual sense but must be treated as one here.
      let transportErr: unknown;
      try {
        res = await this.fetchFn(url, {
          headers,
          signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
        // The body read belongs INSIDE this guard, and the `await` is load-bearing — returning
        // the promise unawaited would settle it outside the try and restore the bug.
        //
        // `AbortSignal.timeout` bounds the whole exchange, not the handshake: NVD sends headers
        // promptly and then streams, so on a 2000-row page the deadline lands here. While this
        // line sat outside the try, that abort rejected `res.json()` with a raw TimeoutError
        // that bypassed the retry loop entirely — five lost ingestion windows between 31 Aug
        // and 4 Sep 2026, every one of them recovered by Cloud Scheduler's retry rather than by
        // `maxRetries`, which was never once consulted.
        if (res.ok) return await res.json();
      } catch (err) {
        transportErr = err;
      }

      attempt++;
      if (attempt > this.maxRetries) {
        throw new Error(
          `NVD request failed after ${this.maxRetries} retries: ${url} → ${
            transportErr !== undefined ? describeError(transportErr) : `HTTP ${res?.status}`
          }`,
        );
      }
      const status = res?.status;
      // Only a *status* failure can be non-retryable. A transport failure carries a status
      // incidentally — the headers arrived, the payload did not — so judging it by that status
      // would turn an aborted 200 into a permanent "no retry for HTTP 200".
      if (
        res &&
        transportErr === undefined &&
        status !== 403 &&
        status !== 503 &&
        status !== 429 &&
        (status ?? 0) < 500
      ) {
        throw new Error(`NVD request failed (no retry for HTTP ${status}): ${url}`);
      }
      const delay = this.backoffBaseMs * 2 ** (attempt - 1) * (1 + Math.random() * 0.25);
      this.log.warn(
        `NVD ${transportErr !== undefined ? "transport error" : status} on attempt ${attempt}, backing off ${Math.round(delay)}ms`,
      );
      await this.sleepFn(delay);
    }
  }

  /** Page through /cves/2.0, yielding each page. */
  async *cvePages(params: Record<string, string>): AsyncGenerator<NvdCvePage> {
    const pageSize = 2000;
    let startIndex = 0;
    for (;;) {
      const qs = new URLSearchParams({
        ...params,
        resultsPerPage: String(pageSize),
        startIndex: String(startIndex),
      });
      const page = (await this.get(`${BASE_CVES}?${qs.toString()}`)) as NvdCvePage;
      yield page;
      startIndex += page.resultsPerPage;
      if (startIndex >= page.totalResults || page.vulnerabilities.length === 0) return;
    }
  }

  // `cvesForCpe(virtualMatchString, extraParams)` and `cvesModifiedSince(from, to)` used to live
  // here. Both were three lines draining `cvePages` into one array, and both became
  // out-of-memory aborts in production: WAL-95 on the incremental path, which crashed
  // `walrus-api` twice a day, and WAL-97 on the backfill path. Nothing bounded what NVD returned,
  // so the array was as large as the query was broad.
  //
  // They are deleted rather than deprecated because the hazard was never the implementation — it
  // was that the accumulating call was the obvious one to reach for, sitting in autocomplete next
  // to the streaming one. Callers page with `cvePages` and ingest per page. A test that wants a
  // finished list builds one itself from a fake transport; see `collect` in `nvd-client.test.ts`.

  /**
   * A single CVE by id. Used by the CVSS enrichment pass to reach CVEs that the
   * CPE-keyed paths never see: NVD "Deferred" records carry full CVSS metrics
   * but no CPE configurations, so a `virtualMatchString` query cannot find them.
   * Returns null when NVD does not know the id.
   */
  async cveById(cveId: string): Promise<NvdCveItem | null> {
    for await (const page of this.cvePages({ cveId })) {
      if (page.vulnerabilities.length > 0) return page.vulnerabilities[0];
    }
    return null;
  }

  /** Raw CPE dictionary query (alias/pair verification support). */
  async cpeDictionary(cpeMatchString: string): Promise<unknown> {
    const qs = new URLSearchParams({ cpeMatchString, resultsPerPage: "500" });
    return this.get(`${BASE_CPES}?${qs.toString()}`);
  }
}
