import { config } from "../config/index.js";
import type { Pool } from "pg";
import { log } from "../common/log.js";
import { runVulnBackfillJob } from "../services/vuln-backfill.js";

export interface BackfillLauncher {
  launch(jobId: string): Promise<string>;
}

/** Development launcher: execute after the HTTP response on the local Node process. */
export class LocalBackfillLauncher implements BackfillLauncher {
  constructor(
    private readonly pool: Pool,
    private readonly run = runVulnBackfillJob,
  ) {}

  async launch(jobId: string): Promise<string> {
    setImmediate(() => {
      void this.run(this.pool, jobId).catch((error: unknown) => {
        log.error({ err: error, jobId }, "Local vulnerability backfill failed");
      });
    });
    return `local:${jobId}`;
  }
}

/** Launches the Terraform-managed Cloud Run Job with this database job id. */
export class CloudRunBackfillLauncher implements BackfillLauncher {
  async launch(jobId: string): Promise<string> {
    if (!config.GCP_PROJECT || !config.GCP_REGION || !config.VULN_BACKFILL_JOB) {
      throw new Error("GCP_PROJECT, GCP_REGION and VULN_BACKFILL_JOB are required");
    }
    const tokenResponse = await fetch(
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      { headers: { "Metadata-Flavor": "Google" }, signal: AbortSignal.timeout(5_000) },
    );
    if (!tokenResponse.ok)
      throw new Error(`Failed to obtain GCP access token (${tokenResponse.status})`);
    const token = (await tokenResponse.json()) as { access_token: string };
    const jobName = `projects/${config.GCP_PROJECT}/locations/${config.GCP_REGION}/jobs/${config.VULN_BACKFILL_JOB}`;
    const response = await fetch(`https://run.googleapis.com/v2/${jobName}:run`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ overrides: { containerOverrides: [{ args: ["--job-id", jobId] }] } }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok)
      throw new Error(`Cloud Run Job launch failed (${response.status}): ${await response.text()}`);
    const operation = (await response.json()) as { name?: string };
    return operation.name ?? jobName;
  }
}
