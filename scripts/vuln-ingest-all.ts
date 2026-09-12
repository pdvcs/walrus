#!/usr/bin/env tsx
/**
 * vuln-ingest-all.ts — drive a full CVE ingestion for EVERY tracked package over the admin API.
 *
 * Usage:
 *   npm run vuln:ingest-all                                   # localhost:8080, full NVD history
 *   npm run vuln:ingest-all -- --since 2015-01-01             # bound the NVD walk (much faster)
 *   npm run vuln:ingest-all -- --base-url https://walrus.example.com
 *   npm run vuln:ingest-all -- --sources nvd,osv              # skip kev
 *   npm run vuln:ingest-all -- --no-wait                      # start the NVD job, don't poll
 *
 * The token comes from WALRUS_API_TOKEN, or --token. Mint one at /admin/v1/tokens while signed
 * in to the admin UI; it is never printed or logged by this script.
 *
 * Why an API script rather than a DB one: walrus runs on Cloud Run with no shell, so anything
 * that has to work in a deployed environment has to be reachable over HTTP. `npm run
 * vuln:backfill` talks to Postgres directly and is the better tool locally — this one is the
 * same operation shaped so it also works against dev/prod.
 *
 * Why three calls rather than one: the sources cover different packages, and no single endpoint
 * spans them.
 *   - NVD reaches a package only through its CPE pairs, so a package with no CPE is invisible
 *     to it. `POST /admin/v1/vuln-backfill` with no `package` walks every pair of every package.
 *   - OSV reaches a package only through its `osv_ecosystem`/`osv_name` mapping.
 *     `POST /admin/v1/vuln-sync/osv` walks every package that has one.
 *   - KEV is a global feed, enriching CVEs already ingested.
 * Several packages are tracked by exactly one of the first two (jq has CPEs and no OSV mapping;
 * zoxide, eza, fd, difftastic and micro have OSV mappings and no CPE), so running only one
 * source silently leaves those packages at zero.
 *
 * And why the backfill rather than `vuln-sync/nvd`: the incremental NVD walk is cursor-based and
 * cannot reach CVEs published before a package was tracked, which is every CVE that matters for
 * a package added today.
 */
import { config } from "../src/config/index.js";

const DEFAULT_BASE_URL = "http://localhost:8080";
/** Backfills are long; poll slowly enough to be cheap and often enough to feel live. */
const POLL_INTERVAL_MS = 5_000;

const c = {
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

export type Source = "nvd" | "osv" | "kev";
const ALL_SOURCES: Source[] = ["nvd", "osv", "kev"];

// ── Argument parsing ──────────────────────────────────────────────────────────

function valueAfter(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i < 0) return undefined;
  const value = args[i + 1];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value`);
  return value;
}

export function parseSince(args: string[]): string | undefined {
  const value = valueAfter(args, "--since");
  // Validated here rather than at the server: a typo should cost nothing, and the endpoint
  // would otherwise reject it after the token round-trip.
  if (value !== undefined && !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    throw new Error("--since requires a YYYY-MM-DD value");
  }
  return value;
}

export function parseBaseUrl(args: string[]): string {
  const raw = valueAfter(args, "--base-url") ?? process.env.WALRUS_BASE_URL ?? DEFAULT_BASE_URL;
  // Trailing slashes would produce "//admin/v1/..." paths, which some proxies normalise and
  // others 404 on.
  return raw.replace(/\/+$/, "");
}

export function parseSources(args: string[]): Source[] {
  const raw = valueAfter(args, "--sources");
  if (raw === undefined) return ALL_SOURCES;
  const requested = raw
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  if (requested.length === 0) throw new Error("--sources requires at least one source");
  const unknown = requested.filter((s) => !ALL_SOURCES.includes(s as Source));
  if (unknown.length > 0) {
    throw new Error(`Unknown source(s): ${unknown.join(", ")}. Valid: ${ALL_SOURCES.join(", ")}`);
  }
  // Preserve canonical order, not the order typed: nvd before osv keeps the long job started
  // first, and de-duplicates a repeated source.
  return ALL_SOURCES.filter((s) => requested.includes(s));
}

export function resolveToken(args: string[]): string {
  const token = valueAfter(args, "--token") ?? process.env.WALRUS_API_TOKEN;
  if (!token) {
    throw new Error(
      "No API token. Set WALRUS_API_TOKEN or pass --token <token>.\n" +
        "  Mint one at /admin/v1/tokens while signed in to the admin UI.",
    );
  }
  return token;
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

interface ApiResult {
  status: number;
  body: unknown;
}

async function post(
  baseUrl: string,
  path: string,
  token: string,
  body?: unknown,
): Promise<ApiResult> {
  return request("POST", baseUrl, path, token, body);
}

async function request(
  method: string,
  baseUrl: string,
  path: string,
  token: string,
  body?: unknown,
): Promise<ApiResult> {
  const res = await fetch(`${baseUrl}${path}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      // Explicit, because these endpoints answer a browser with a 303 redirect to the admin UI
      // when Accept includes text/html. Asking for JSON is what keeps this a machine client.
      Accept: "application/json",
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  let parsed: unknown = text;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    // Leave it as text — an HTML error page or a proxy's plain-text 502 is worth showing raw.
  }
  return { status: res.status, body: parsed };
}

/**
 * Render a value only if it is a scalar. Everything here comes from a parsed JSON body, so a
 * plain String() would cheerfully print "[object Object]" into an operator's terminal for any
 * field the server later nests.
 */
function scalar(value: unknown): string | undefined {
  switch (typeof value) {
    case "string":
      return value;
    case "number":
    case "boolean":
    case "bigint":
      return String(value);
    default:
      return undefined;
  }
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : (scalar(err) ?? "unknown error");
}

function errorOf(body: unknown): string {
  if (body && typeof body === "object") {
    const o = body as { error?: unknown; message?: unknown; code?: unknown };
    for (const field of [o.error, o.message, o.code]) {
      if (typeof field === "string") return field;
    }
  }
  return typeof body === "string" && body ? body.slice(0, 300) : "(no message)";
}

// ── Preflight ─────────────────────────────────────────────────────────────────

/**
 * Fail on a bad token or an unreachable host before starting anything, so a typo does not leave
 * a half-run ingestion behind. `GET /admin/v1/vulns` is the cheapest authenticated read.
 */
async function preflight(baseUrl: string, token: string): Promise<boolean> {
  let res: ApiResult;
  try {
    res = await request("GET", baseUrl, "/admin/v1/vulns", token);
  } catch (err) {
    console.error(c.red(`✗ Cannot reach ${baseUrl}: ${messageOf(err)}`));
    console.error(c.dim("  Is the server running? (npm run dev)"));
    return false;
  }
  if (res.status === 401 || res.status === 403) {
    console.error(c.red(`✗ Token rejected (HTTP ${res.status}).`));
    console.error(c.dim("  Mint a fresh one at /admin/v1/tokens."));
    // Worth saying out loud: in dev this is usually not expiry. With WALRUS_SESSION_SECRET unset
    // the server generates a process-local signing key at boot, so every tsx-watch restart —
    // including the one caused by editing a file mid-run — invalidates every existing token.
    console.error(
      c.dim(
        "  In dev, a `tsx watch` restart invalidates tokens unless WALRUS_SESSION_SECRET is set.",
      ),
    );
    return false;
  }
  if (res.status >= 400) {
    console.error(c.red(`✗ Preflight failed (HTTP ${res.status}): ${errorOf(res.body)}`));
    return false;
  }
  return true;
}

// ── NVD backfill ──────────────────────────────────────────────────────────────

interface BackfillJob {
  id?: unknown;
  status?: unknown;
  cpe_pairs_total?: unknown;
  cpe_pairs_done?: unknown;
  error_message?: unknown;
}

function jobField(job: BackfillJob | undefined, key: keyof BackfillJob): string | undefined {
  return scalar(job?.[key]);
}

/**
 * Start the all-packages NVD backfill and, unless --no-wait, poll it to completion.
 *
 * A 409 is reported as a skip rather than a failure: another backfill already holding the "nvd"
 * lock is doing this script's job, and turning that into a non-zero exit would make a retry look
 * like a broken deployment.
 */
async function runNvdBackfill(
  baseUrl: string,
  token: string,
  opts: { since?: string; wait: boolean },
): Promise<boolean> {
  const body = opts.since ? { since: opts.since } : {};
  const started = await post(baseUrl, "/admin/v1/vuln-backfill", token, body);

  if (started.status === 409) {
    console.log(c.yellow("  ⚠ An NVD backfill is already running — leaving it to finish."));
    return true;
  }
  if (started.status !== 202) {
    console.error(c.red(`  ✗ Failed to start (HTTP ${started.status}): ${errorOf(started.body)}`));
    return false;
  }

  const job = (started.body as { job?: BackfillJob }).job;
  const id = jobField(job, "id");
  console.log(`  started job ${id ?? "(unknown id)"}${opts.since ? ` since ${opts.since}` : ""}`);

  if (!opts.wait) {
    console.log(c.dim(`  not waiting — poll ${baseUrl}/admin/v1/vuln-backfill/${id ?? "<id>"}`));
    return true;
  }
  if (id === undefined) {
    console.error(c.red("  ✗ Server returned no job id, cannot poll"));
    return false;
  }
  return pollBackfill(baseUrl, token, id);
}

async function pollBackfill(baseUrl: string, token: string, id: string): Promise<boolean> {
  const startedAt = Date.now();
  let lastStatus: string | undefined;

  for (;;) {
    await sleep(POLL_INTERVAL_MS);
    const res = await request("GET", baseUrl, `/admin/v1/vuln-backfill/${id}`, token);
    if (res.status >= 400) {
      console.error(c.red(`  ✗ Status check failed (HTTP ${res.status}): ${errorOf(res.body)}`));
      return false;
    }
    const job = ((res.body as { job?: BackfillJob }).job ?? res.body) as BackfillJob;
    const status = jobField(job, "status") ?? "unknown";
    const elapsed = Math.round((Date.now() - startedAt) / 1000);

    // Progress, not just status: a backfill walking 25 CPE pairs sits in "running" for minutes,
    // and a line that never changes is indistinguishable from a hung job.
    const progress = [jobField(job, "cpe_pairs_done"), jobField(job, "cpe_pairs_total")];
    const marker = `${status} ${progress[0] ?? ""}/${progress[1] ?? ""}`;
    if (marker !== lastStatus) {
      console.log(
        c.dim(
          `  ${status}` +
            (progress[1] ? ` — ${progress[0] ?? 0}/${progress[1]} CPE pairs` : "") +
            ` (${elapsed}s)`,
        ),
      );
      lastStatus = marker;
    }

    // Terminal states are whatever the server calls them; match on the shape rather than an
    // exhaustive list so a new status name does not hang this loop forever.
    if (/succeed|complete|done/i.test(status)) {
      const pairs = jobField(job, "cpe_pairs_done");
      console.log(
        c.green(`  ✓ NVD backfill finished in ${elapsed}s`) +
          (pairs ? `: ${pairs} CPE pair(s) walked` : ""),
      );
      return true;
    }
    if (/fail|error|cancel/i.test(status)) {
      console.error(
        c.red(`  ✗ NVD backfill ${status}: ${jobField(job, "error_message") ?? "no detail"}`),
      );
      return false;
    }
  }
}

// ── OSV / KEV sync ────────────────────────────────────────────────────────────

/**
 * These run inline and return when done. 207 means "some source in the set failed", which for a
 * single named source cannot happen, but it is treated as a failure for the same reason the route
 * distinguishes it: a partial result is not a success.
 */
async function runSync(baseUrl: string, token: string, source: Source): Promise<boolean> {
  const res = await post(baseUrl, `/admin/v1/vuln-sync/${source}`, token);

  if (res.status === 409) {
    console.log(c.yellow(`  ⚠ A ${source} sync is already running — leaving it to finish.`));
    return true;
  }
  if (res.status !== 200) {
    console.error(c.red(`  ✗ ${source} sync failed (HTTP ${res.status}): ${errorOf(res.body)}`));
    return false;
  }

  const outcomes = (res.body as { outcomes?: unknown }).outcomes;
  if (Array.isArray(outcomes)) {
    for (const outcome of outcomes as Array<Record<string, unknown>>) {
      const detail = summarise(outcome);
      console.log(
        `  ${outcome.ok ? c.green("✓") : c.red("✗")} ${source}` +
          (detail ? ` ${c.dim(detail)}` : ""),
      );
    }
  } else {
    console.log(c.green(`  ✓ ${source} sync complete`));
  }
  return true;
}

/**
 * Flatten one outcome's scalar counts into `key=value` pairs. The interesting numbers sit one
 * level down in `summary` (packages, vulns, affectsUpserted, …), so that object is walked rather
 * than skipped — printing only the top level reports a successful sync with no figures at all,
 * which is indistinguishable from one that did nothing.
 */
export function summarise(outcome: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(outcome)) {
    if (key === "ok" || key === "source") continue;
    if (value !== null && typeof value === "object") {
      for (const [innerKey, innerValue] of Object.entries(value as Record<string, unknown>)) {
        const rendered = scalar(innerValue);
        if (rendered !== undefined) parts.push(`${innerKey}=${rendered}`);
      }
      continue;
    }
    const rendered = scalar(value);
    if (rendered !== undefined) parts.push(`${key}=${rendered}`);
  }
  return parts.join(" ");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Entry point ───────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2);

  let baseUrl: string;
  let since: string | undefined;
  let sources: Source[];
  let token: string;
  try {
    baseUrl = parseBaseUrl(args);
    since = parseSince(args);
    sources = parseSources(args);
    token = resolveToken(args);
  } catch (err) {
    console.error(c.red(`✗ ${err instanceof Error ? err.message : String(err)}`));
    process.exit(1);
  }
  const wait = !args.includes("--no-wait");

  console.log(c.bold(`\nIngesting vulnerabilities for all tracked packages`));
  console.log(`  target:  ${baseUrl}`);
  console.log(`  sources: ${sources.join(", ")}`);

  if (sources.includes("nvd") && !since) {
    console.log(
      c.yellow(
        "  ⚠ No --since: the NVD walk covers all history in 120-day windows and takes a while.",
      ),
    );
  }
  // The server pays for this, not the script, but an operator running it locally is usually the
  // same person who can fix the missing key.
  if (sources.includes("nvd") && !config.NVD_API_KEY) {
    console.log(
      c.yellow("  ⚠ No NVD_API_KEY in the environment — NVD is rate-limited to 5 req/30s."),
    );
  }
  console.log("");

  if (!(await preflight(baseUrl, token))) process.exit(1);

  const failed: Source[] = [];
  for (const source of sources) {
    console.log(c.bold(source === "nvd" ? "NVD backfill (all CPE pairs)" : `${source} sync`));
    const ok =
      source === "nvd"
        ? await runNvdBackfill(baseUrl, token, { since, wait })
        : await runSync(baseUrl, token, source);
    if (!ok) failed.push(source);
    console.log("");
  }

  if (failed.length > 0) {
    console.log(c.red(`✗ Failed: ${failed.join(", ")}`));
    process.exit(1);
  }
  console.log(c.green(`✓ All ${sources.length} source(s) ingested`));
  console.log(
    c.dim(
      "  Spot-check a package: " +
        `curl -sS ${baseUrl}/api/v1/packages/starship/vulns\n` +
        "  Packages with neither a CPE nor an OSV mapping stay empty by design.",
    ),
  );
}

if (require.main === module) {
  main().catch((err) => {
    console.error(c.red("Unexpected error:"), err);
    process.exit(1);
  });
}
