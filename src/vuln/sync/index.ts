/**
 * Vuln sync orchestrator. Dispatches a sync source (nvd | kev | osv | cvss | all)
 * to an
 * injected implementation and returns per-source outcomes. Shared by the
 * `/internal/vuln-sync/:source` route, the admin trigger, and tests (which inject
 * fixture-backed fakes). Mirrors walrus's dependency-injected route pattern —
 * no NVD client or network is constructed here. See plan §5.
 */
import { log } from "../../common/log.js";
import { VulnSyncAlreadyRunningError } from "./lock.js";

export type VulnSyncSource = "nvd" | "kev" | "osv" | "cvss" | "all";
export const SYNC_SOURCES: VulnSyncSource[] = ["nvd", "kev", "osv", "cvss", "all"];

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
  cvss?: () => Promise<Record<string, number>>;
}

export function isVulnSyncSource(s: string): s is VulnSyncSource {
  return (SYNC_SOURCES as string[]).includes(s);
}

async function runOne(
  source: "nvd" | "kev" | "osv" | "cvss",
  impls: VulnSyncImpls,
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
    const summary = await impl();
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
): Promise<SourceOutcome[]> {
  if (source === "all") {
    const outcomes: SourceOutcome[] = [];
    for (const s of ["nvd", "kev", "osv"] as const) {
      outcomes.push(await runOne(s, impls));
    }
    return outcomes;
  }
  return [await runOne(source, impls)];
}
