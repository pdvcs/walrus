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
      let networkErr: unknown;
      try {
        res = await this.fetchFn(url, {
          headers,
          signal: AbortSignal.timeout(this.requestTimeoutMs),
        });
      } catch (err) {
        networkErr = err;
      }

      if (res?.ok) return res.json();

      attempt++;
      if (attempt > this.maxRetries) {
        throw new Error(
          `NVD request failed after ${this.maxRetries} retries: ${url} → ${res ? `HTTP ${res.status}` : String(networkErr)}`,
        );
      }
      const status = res?.status;
      if (res && status !== 403 && status !== 503 && status !== 429 && (status ?? 0) < 500) {
        throw new Error(`NVD request failed (no retry for HTTP ${status}): ${url}`);
      }
      const delay = this.backoffBaseMs * 2 ** (attempt - 1) * (1 + Math.random() * 0.25);
      this.log.warn(
        `NVD ${status ?? "network error"} on attempt ${attempt}, backing off ${Math.round(delay)}ms`,
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

  /** All CVEs matching a virtual match string (per-product backfill). */
  async cvesForCpe(
    virtualMatchString: string,
    extraParams: Record<string, string> = {},
  ): Promise<NvdCveItem[]> {
    const items: NvdCveItem[] = [];
    for await (const page of this.cvePages({ virtualMatchString, ...extraParams })) {
      items.push(...page.vulnerabilities);
    }
    return items;
  }

  /** CVEs modified in a window (incremental sync). */
  async cvesModifiedSince(lastModStartDate: string, lastModEndDate: string): Promise<NvdCveItem[]> {
    const items: NvdCveItem[] = [];
    for await (const page of this.cvePages({ lastModStartDate, lastModEndDate })) {
      items.push(...page.vulnerabilities);
    }
    return items;
  }

  /** Raw CPE dictionary query (alias/pair verification support). */
  async cpeDictionary(cpeMatchString: string): Promise<unknown> {
    const qs = new URLSearchParams({ cpeMatchString, resultsPerPage: "500" });
    return this.get(`${BASE_CPES}?${qs.toString()}`);
  }
}
