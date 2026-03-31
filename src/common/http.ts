import { config } from "../config/index.js";
import { log } from "./log.js";

export interface HttpRetryOptions {
  timeoutMs?: number;
  maxRetries?: number;
  retryBaseDelayMs?: number;
}

export class HttpRequestError extends Error {
  constructor(
    message: string,
    public readonly status?: number,
  ) {
    super(message);
    this.name = "HttpRequestError";
  }
}

const DEFAULT_TIMEOUT_MS = config.DISCOVERY_HTTP_TIMEOUT_MS;
const DEFAULT_MAX_RETRIES = config.DISCOVERY_HTTP_MAX_RETRIES;
const DEFAULT_RETRY_BASE_DELAY_MS = config.DISCOVERY_HTTP_RETRY_BASE_DELAY_MS;

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
      const response = await fetch(url, {
        ...init,
        signal: controller.signal,
      });

      if (response.ok) {
        return response;
      }

      const body = await safeText(response);
      const message = `HTTP ${response.status} from ${url}${body ? `: ${body}` : ""}`;
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
    return err.message;
  }
  return String(err);
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
