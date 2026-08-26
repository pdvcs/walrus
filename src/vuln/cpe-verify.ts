/**
 * CPE pair verification against the NVD CPE dictionary (WAL-45).
 *
 * A syntactically valid `vendor:product` pair can name the wrong product, and nothing
 * downstream notices: the targeted backfill walks zero results, reports success, and
 * marks the package covered. This probe catches that at authoring time by asking NVD
 * whether the pair's match string has any dictionary entries.
 *
 * Deliberately a *warning*, never a failure: zero hits also happens legitimately for
 * products NVD has never had to name (small utilities whose CVEs carry no CPE
 * configurations), so absence of evidence cannot distinguish a typo from an obscure
 * but correct pair. The wording says "verify", not "invalid".
 */
import { NvdClient } from "./sync/nvd-client.js";
import { buildMatchString } from "./cpe.js";

export type CpePairStatus = "verified" | "unverifiable" | "unchecked";

export interface CpePairVerdict {
  /** The original `vendor:product` input. */
  pair: string;
  matchString: string;
  status: CpePairStatus;
  /** Dictionary entries found; null when the lookup itself failed. */
  hits: number | null;
  /** Human-readable explanation for non-verified outcomes. */
  detail?: string;
}

export interface CpeVerifyResult {
  results: CpePairVerdict[];
  verified: number;
  unverifiable: number;
  unchecked: number;
}

const UNVERIFIABLE_DETAIL =
  "No CPE dictionary entry found — double-check vendor/product spelling against NVD." +
  " This also occurs legitimately for products NVD has never had to name.";

/** Probe one pair; lookup failures are reported per-pair rather than aborting the rest. */
async function verifyOne(
  nvd: Pick<NvdClient, "cpeDictionary">,
  pair: string,
): Promise<CpePairVerdict> {
  const [vendor, product] = pair.split(":");
  const matchString = buildMatchString(vendor, product);
  try {
    const res = (await nvd.cpeDictionary(matchString)) as { totalResults?: unknown };
    const hits = typeof res?.totalResults === "number" ? res.totalResults : null;
    if (hits !== null && hits > 0) {
      return { pair, matchString, status: "verified", hits };
    }
    return { pair, matchString, status: "unverifiable", hits, detail: UNVERIFIABLE_DETAIL };
  } catch (err) {
    return {
      pair,
      matchString,
      status: "unchecked",
      hits: null,
      detail:
        "Could not be checked against the NVD dictionary (" +
        `${err instanceof Error ? err.message : String(err)})`,
    };
  }
}

/**
 * Verify each CPE pair against the NVD CPE dictionary. One request per pair through
 * the client's own rate limiter; per-pair failures never abort the walk.
 */
export async function verifyCpePairs(
  nvd: Pick<NvdClient, "cpeDictionary">,
  pairs: string[],
): Promise<CpeVerifyResult> {
  const results: CpePairVerdict[] = [];
  for (const pair of pairs) {
    results.push(await verifyOne(nvd, pair));
  }
  return {
    results,
    verified: results.filter((r) => r.status === "verified").length,
    unverifiable: results.filter((r) => r.status === "unverifiable").length,
    unchecked: results.filter((r) => r.status === "unchecked").length,
  };
}

/**
 * The production probe used when no injection is supplied: same client configuration
 * the sync paths use (keyless or NVD_API_KEY, shared backoff/rate-limit behaviour).
 */
export function defaultCpeProbe(pairs: string[]): Promise<CpeVerifyResult> {
  return verifyCpePairs(new NvdClient(), pairs);
}
