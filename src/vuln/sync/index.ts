/**
 * Vuln sync orchestrator. Dispatches a sync source (nvd | kev | osv | cvss | all)
 * to an
 * injected implementation and returns per-source outcomes. Shared by the
 * `/internal/vuln-sync/:source` route, the admin trigger, and tests (which inject
 * fixture-backed fakes). Mirrors walrus's dependency-injected route pattern —
 * no NVD client or network is constructed here. See plan §5.
 */
import { log } from "../../common/log.js";
import type { CvssProposal, GateDelta } from "./cvss-enrich.js";
import { VulnSyncAlreadyRunningError } from "./lock.js";

export type VulnSyncSource = "nvd" | "kev" | "osv" | "cvss" | "all";
export const SYNC_SOURCES: VulnSyncSource[] = ["nvd", "kev", "osv", "cvss", "all"];

/**
 * Per-run options. Only `cvss` honours these; the routes reject them for any other
 * source rather than accepting a flag they would silently ignore — a caller who
 * believes they asked for a dry run must never get a live write instead.
 */
export interface VulnSyncOptions {
  /** Report what would change without writing. `cvss` only. */
  dryRun?: boolean;
  /** Bound the walk. `cvss` only. */
  limit?: number;
}

/**
 * Read-only answer to "what would enrichment do?". Carries the gate delta because
 * enrichment can newly satisfy the >= 9.0 download gate, turning a version that
 * serves today into a 403 — the one thing an operator must see before applying.
 */
export interface CvssPreview {
  candidates: number;
  fetched: number;
  proposals: CvssProposal[];
  newly_blocked: GateDelta[];
}

export interface SourceOutcome {
  source: "nvd" | "kev" | "osv" | "cvss";
  ok: boolean;
  summary?: Record<string, number>;
  error?: string;
  code?: "already_running" | "unavailable" | "failed";
}

/**
 * One sync function per source, each closing over the pool + any upstream client.
 * Returns a numeric summary for reporting. Injected from main.ts (real) or tests.
 */
export interface VulnSyncImpls {
  nvd?: () => Promise<Record<string, number>>;
  kev?: () => Promise<Record<string, number>>;
  osv?: () => Promise<Record<string, number>>;
  /** CVSS enrichment for CVEs with no severity — a repair pass, not routine. */
  cvss?: (opts?: VulnSyncOptions) => Promise<Record<string, number>>;
  /**
   * Dry run for `cvss`, kept a separate entry point rather than a flag on the run:
   * it returns detail no numeric summary can carry, and being a distinct function
   * means a preview can never fall through to a write.
   */
  cvssPreview?: (opts?: VulnSyncOptions) => Promise<CvssPreview>;
}

export function isVulnSyncSource(s: string): s is VulnSyncSource {
  return (SYNC_SOURCES as string[]).includes(s);
}

/**
 * Validate `{dry_run, limit}` off a request body. Shared by the internal and admin
 * routes so the two cannot drift on which combinations are legal.
 *
 * Both options are rejected outright for a source that cannot honour them. Ignoring
 * `dry_run` on, say, `nvd` would run a live sync for an operator who asked for a
 * preview — the failure mode this whole option exists to prevent.
 */
export function parseVulnSyncOptions(
  source: VulnSyncSource,
  body: unknown,
): { ok: true; opts: VulnSyncOptions } | { ok: false; error: string } {
  const raw = (body ?? {}) as { dry_run?: unknown; limit?: unknown };

  let dryRun = false;
  if (raw.dry_run !== undefined) {
    // Accept the string forms too, for clients that send "true"/"false" as JSON
    // strings. (A form-field checkbox would also need express.urlencoded().)
    if (raw.dry_run === true || raw.dry_run === "true") dryRun = true;
    else if (raw.dry_run !== false && raw.dry_run !== "false")
      return { ok: false, error: "dry_run must be a boolean" };
  }

  let limit: number | undefined;
  if (raw.limit !== undefined && raw.limit !== "") {
    const value = Number(raw.limit);
    if (!Number.isInteger(value) || value <= 0)
      return { ok: false, error: "limit must be a positive integer" };
    limit = value;
  }

  if (source !== "cvss") {
    if (dryRun)
      return {
        ok: false,
        error: `dry_run is only supported for the 'cvss' source, not '${source}'`,
      };
    if (limit !== undefined)
      return {
        ok: false,
        error: `limit is only supported for the 'cvss' source, not '${source}'`,
      };
  }

  return { ok: true, opts: { dryRun, limit } };
}

async function runOne(
  source: "nvd" | "kev" | "osv" | "cvss",
  impls: VulnSyncImpls,
  opts?: VulnSyncOptions,
): Promise<SourceOutcome> {
  const impl = impls[source];
  if (!impl)
    return {
      source,
      ok: false,
      code: "unavailable",
      error: `sync source '${source}' is not available`,
    };
  try {
    const summary = await impl(opts);
    return { source, ok: true, summary };
  } catch (err) {
    log.error({ source, err }, "vuln sync failed");
    return {
      source,
      ok: false,
      code: err instanceof VulnSyncAlreadyRunningError ? "already_running" : "failed",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Run one source, or all three in order (nvd → kev → osv). `all` continues past
 * a per-source failure and reports each; only failing sources are marked not-ok.
 *
 * `cvss` is deliberately excluded from `all`: it is a repair pass that walks every
 * severity-less CVE one request at a time, and folding it into routine syncs would
 * lengthen them for no routine benefit. Trigger it explicitly.
 */
export async function runVulnSync(
  source: VulnSyncSource,
  impls: VulnSyncImpls,
  opts?: VulnSyncOptions,
): Promise<SourceOutcome[]> {
  if (source === "all") {
    const outcomes: SourceOutcome[] = [];
    for (const s of ["nvd", "kev", "osv"] as const) {
      outcomes.push(await runOne(s, impls));
    }
    return outcomes;
  }
  return [await runOne(source, impls, opts)];
}
