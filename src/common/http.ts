import { config } from "../config/index.js";
import { log } from "./log.js";
import { type EgressPurpose, getEgressState, matchEgressRule } from "./egress-rules.js";

export interface HttpRetryOptions {
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseDelayMs?: number;
}

export class HttpRequestError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
    /** The upstream refused because a rate limit is exhausted, not because the request was bad. */
    public readonly rateLimited = false,
  ) {
    super(message);
    this.name = "HttpRequestError";
  }
}

const DEFAULT_TIMEOUT_MS = config.DISCOVERY_HTTP_TIMEOUT_MS;
const DEFAULT_MAX_RETRIES = config.DISCOVERY_HTTP_MAX_RETRIES;
const DEFAULT_RETRY_BASE_DELAY_MS = config.DISCOVERY_HTTP_RETRY_BASE_DELAY_MS;

export interface CreateEgressFetchOptions {
  /** Which class of egress traffic this fetch belongs to (WAL-113 rule `purpose` restriction). */
  purpose: EgressPurpose;
}

/**
 * The single seam every outbound (public-internet) fetch in walrus goes through. Every later
 * egress layer (declarative rewrite rules, CONNECT proxying, an adopter extension) attaches
 * here, instead of at each of the five call sites that used to open their own `fetch` (WAL-112).
 *
 * Rule matching (WAL-113) consults the *current* egress state on every call via
 * `getEgressState()`, not a snapshot taken when this factory ran — `WALRUS_EGRESS_RULES` is
 * loaded once at boot, but several call sites construct their `createEgressFetch()` instance at
 * module-import time, before that boot step runs.
 */
export function createEgressFetch(options: CreateEgressFetchOptions): typeof fetch {
  const { purpose } = options;
  return async (input, init) => {
    const state = getEgressState();
    const url = urlOf(input);
    const match = matchEgressRule(url, purpose, state.rules);

    if (match) {
      const headers = new Headers(init?.headers);
      for (const [name, value] of Object.entries(match.headers)) {
        headers.set(name, value);
      }
      return fetch(match.rewrittenUrl, { ...init, headers });
    }

    if (state.mode === "strict") {
      throw new HttpRequestError(
        `Egress refused under WALRUS_EGRESS_MODE=strict: no rule matched ${purpose} request to ${url}`,
      );
    }
    if (state.mode === "rules") {
      log.warn({ url, purpose }, "No egress rule matched; proceeding with a direct connection");
    }
    return fetch(input, init);
  };
}

function urlOf(input: Parameters<typeof fetch>[0]): string {
  if (typeof input === "string") return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

const discoveryFetch = createEgressFetch({ purpose: "discovery" });

export async function fetchWithRetry(
  url: string,
  init: RequestInit = {},
  options: HttpRetryOptions = {},
): Promise<Response> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxRetries = options.maxRetries ?? DEFAULT_MAX_RETRIES;
  const retryBaseDelayMs = options.retryBaseDelayMs ?? DEFAULT_RETRY_BASE_DELAY_MS;

  for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await discoveryFetch(url, {
        ...init,
        signal: controller.signal,
      });

      if (response.ok) {
        return response;
      }

      const body = await safeText(response);
      const message = `HTTP ${response.status} from ${url}${body ? `: ${body}` : ""}`;

      // A rate limit is not the same failure as an upstream being broken, and reads very
      // differently to whoever the alert wakes: nothing is wrong with walrus or with the
      // upstream, the budget is simply spent until a known time. Naming it here means the
      // operator can tell the two apart without opening the log (WAL-103).
      //
      // It also must not be retried. The existing backoff is seconds; a rate-limit window is
      // minutes to an hour, so every retry is guaranteed to fail and spends quota that the
      // *next* package's discovery needs. GitHub returns 403 for this, not 429.
      if (isRateLimited(response)) {
        const resetAt = rateLimitResetAt(response);
        log.error(
          { url, status: response.status, resetAt },
          "Upstream rate limit exhausted; not retrying until it resets",
        );
        throw new HttpRequestError(
          `${message}${resetAt ? ` (rate limit resets at ${resetAt})` : ""}`,
          response.status,
          true,
        );
      }

      if (attempt < maxRetries && isRetryableStatus(response.status)) {
        log.warn(
          {
            url,
            status: response.status,
            attempt: attempt + 1,
            maxAttempts: maxRetries + 1,
          },
          "Retrying HTTP request after retryable status",
        );
        await sleep(retryBaseDelayMs * 2 ** attempt);
        continue;
      }

      throw new HttpRequestError(message, response.status);
    } catch (err) {
      // A failure already classified above — an HTTP status, or an exhausted rate limit —
      // must be rethrown as it is. Re-wrapping it discards `status` and `rateLimited`, which
      // is not cosmetic: `json-api.ts` treats a 404 release feed as "no releases yet" by
      // testing `err.status === 404`, and that branch could never be reached because the
      // status had already been stripped on the way out.
      if (err instanceof HttpRequestError) {
        throw err;
      }
      const message = normalizeFetchError(err, timeoutMs, url);
      if (attempt < maxRetries && isRetryableError(err)) {
        log.warn(
          {
            url,
            error: message,
            attempt: attempt + 1,
            maxAttempts: maxRetries + 1,
          },
          "Retrying HTTP request after network/timeout error",
        );
        await sleep(retryBaseDelayMs * 2 ** attempt);
        continue;
      }
      throw new HttpRequestError(message);
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  throw new HttpRequestError(`Request failed after retries: ${url}`);
}

export async function fetchJsonWithRetry<T>(
  url: string,
  init: RequestInit = {},
  options: HttpRetryOptions = {},
): Promise<T> {
  const response = await fetchWithRetry(url, init, options);
  return response.json() as Promise<T>;
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

/**
 * A refusal caused by an exhausted quota rather than by the request.
 *
 * `x-ratelimit-remaining: 0` is the reliable signal — GitHub answers 403 for a spent core-API
 * budget, so status alone cannot distinguish it from a permissions failure, and matching on the
 * body text would break the first time the wording changed.
 */
function isRateLimited(response: Response): boolean {
  if (response.status !== 403 && response.status !== 429) {
    return false;
  }
  return header(response, "x-ratelimit-remaining") === "0";
}

/** The reset instant, when the upstream names one, as an ISO string. */
function rateLimitResetAt(response: Response): string | undefined {
  const reset = header(response, "x-ratelimit-reset");
  if (!reset) return undefined;
  const epochSeconds = Number(reset);
  if (!Number.isFinite(epochSeconds)) return undefined;
  return new Date(epochSeconds * 1000).toISOString();
}

function isRetryableError(err: unknown): boolean {
  if (err instanceof Error && err.name === "AbortError") {
    return true;
  }
  return err instanceof TypeError;
}

function normalizeFetchError(err: unknown, timeoutMs: number, url: string): string {
  if (err instanceof Error && err.name === "AbortError") {
    return `Request timed out after ${timeoutMs}ms: ${url}`;
  }
  if (err instanceof Error) {
    // Node's global `fetch` throws a generic `TypeError: fetch failed` on a connection-level
    // failure and stashes the actual reason (ENOTFOUND, ECONNREFUSED, a TLS error) on
    // `err.cause` — exactly what's needed to tell a misconfigured egress rewrite or proxy apart
    // from a plain outage, and exactly what a bare `err.message` throws away (WAL-116).
    const cause = describeCause(err.cause);
    return cause !== undefined ? `${err.message}: ${cause}` : err.message;
  }
  return String(err);
}

function describeCause(cause: unknown): string | undefined {
  if (cause === undefined) return undefined;
  if (cause instanceof Error) return cause.message;
  if (typeof cause === "string" || typeof cause === "number" || typeof cause === "boolean") {
    return String(cause);
  }
  try {
    return JSON.stringify(cause);
  } catch {
    return undefined;
  }
}

/**
 * Read one header without assuming the response carries any. Not defensive padding: a partial
 * `Response` is the normal shape in tests, and a bare `.headers.get` there fails as an opaque
 * TypeError inside the retry loop rather than as the assertion the test was written to make.
 */
function header(response: Response, name: string): string | null {
  return response.headers?.get(name) ?? null;
}

async function safeText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return "";
  }
}

async function sleep(ms: number): Promise<void> {
  if (ms <= 0) {
    return;
  }
  await new Promise((resolve) => setTimeout(resolve, ms));
}
