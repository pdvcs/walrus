import { config } from "../config/index.js";
import { log } from "./log.js";

/**
 * Upstream API credentials: whether this process has them, and the one-line warning it logs
 * at boot when it does not.
 *
 * Both are optional by design — walrus runs keyless, which is what makes a laptop or a CI run
 * possible without provisioning anything. In a deployment it is almost always an oversight
 * instead, and a quiet one: the rate limits differ by an order of magnitude, so the symptom is
 * slowness and runs cut off at a deadline rather than an error anyone can point at.
 *
 * Deliberately NOT a degradation. `getDegradations` answers "is the self-healing machinery
 * failing?", and a missing key is an operator's standing configuration rather than machinery
 * that stopped — reporting it there would park a permanent banner over an intended state, which
 * is the reasoning that already keeps CVE suppressions out (see services/degradations.ts). It is
 * surfaced the way suppressions and egress are: as its own /app/status object, plus a warning
 * each process logs once at boot, which is the surface a developer actually reads.
 */

/**
 * Present-or-absent only, never the value or any prefix of it: /app/status is public.
 *
 * GITHUB_TOKEN is deliberately absent from this shape. It is mounted only into the walrus-sync
 * job (infra/terraform/cloudrun.tf, `google_cloud_run_v2_job "sync"`), because that is where
 * scheduled discovery runs, so the API service answering this endpoint does not have it and
 * never should. Reporting "no GitHub token" from here would be a false alarm on a correctly
 * configured deployment — exactly the cry-wolf failure this module exists to avoid. The sync
 * job reports its own state the only way it can: `warnIfGithubAnonymous` in its boot log.
 */
export interface UpstreamCredentialStatus {
  nvd_api_key: boolean;
}

function present(value: string | undefined): boolean {
  return value !== undefined && value !== "";
}

/**
 * Read through `config` for NVD and `process.env` for GitHub, matching where each consumer
 * actually reads it — `NvdClient` takes `config.NVD_API_KEY`, `GitHubReleasesStrategy` takes
 * `process.env.GITHUB_TOKEN`. A status that consulted a different source than the code it
 * describes would eventually disagree with it.
 */
export function getUpstreamCredentialStatus(): UpstreamCredentialStatus {
  return { nvd_api_key: present(config.NVD_API_KEY) };
}

/** Rate limits are walrus's own budgets (see NvdClient's RateLimiter), one under each published cap. */
export const NVD_KEYLESS_WARNING =
  "Running without NVD_API_KEY: NVD requests are limited to 4 per 30s instead of 45. " +
  "Vulnerability ingestion runs roughly ten times longer and is far likelier to be cut off " +
  "by the scheduler's attempt deadline, and a cut-off run ingests nothing. Fine for local " +
  "work; set NVD_API_KEY (Secret Manager: walrus-nvd-api-key) for any deployment you rely on.";

export const GITHUB_ANONYMOUS_WARNING =
  "Running without GITHUB_TOKEN: api.github.com allows 60 requests/hour unauthenticated " +
  "instead of 5,000. Package discovery will be throttled and may silently stop seeing new " +
  "releases. Fine for local work; set GITHUB_TOKEN (Secret Manager: walrus-github-token) for " +
  "any deployment you rely on.";

interface Warner {
  warn: (msg: string) => void;
}

/** Call at API-service boot: this process runs the scheduled /internal/vuln-sync/* walks. */
export function warnIfNvdKeyless(logger: Warner = log): void {
  if (present(config.NVD_API_KEY)) return;
  logger.warn(NVD_KEYLESS_WARNING);
}

/** Call at sync-job boot: this process runs package discovery against api.github.com. */
export function warnIfGithubAnonymous(logger: Warner = log): void {
  if (present(process.env.GITHUB_TOKEN)) return;
  logger.warn(GITHUB_ANONYMOUS_WARNING);
}
