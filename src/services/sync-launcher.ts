import { config } from "../config/index.js";
import { log } from "../common/log.js";
import { SyncService } from "./sync-service.js";

export interface SyncLauncher {
  launch(jobId: number, packageName: string): Promise<string>;
}

/**
 * Development launcher: run the sync after the HTTP response, in this same process — same
 * shape as before admin-triggered syncs moved to a Cloud Run Job, kept for local dev where
 * there is no separate Job to launch. The job row already exists (`getService(...).prepareJob`
 * created it before this launcher was called), so this resumes it via `existingJobId` rather
 * than creating a second one.
 */
export class LocalSyncLauncher implements SyncLauncher {
  constructor(private readonly getService: (packageName: string) => SyncService | undefined) {}

  launch(jobId: number, packageName: string): Promise<string> {
    const service = this.getService(packageName);
    if (!service) throw new Error(`Unknown package: ${packageName}`);
    setImmediate(() => {
      void service.run({ triggerType: "admin", existingJobId: jobId }).catch((error: unknown) => {
        log.error({ err: error, jobId, package: packageName }, "Local admin sync failed");
      });
    });
    return Promise.resolve(`local:${jobId}`);
  }
}

/**
 * Launches the Terraform-managed `walrus-sync` Cloud Run Job for one package, passing the
 * database job id through `overrides.containerOverrides` (see `sync-job.ts --job-id`).
 *
 * Why this exists at all: an admin-triggered sync used to run in-process after the triggering
 * request returned its 202 — the same "respond early, keep working" shape `sync-job.ts`'s own
 * header explains is unsafe on Cloud Run, because CPU is throttled once a response is sent.
 * That starved exactly the packages large enough to still be running when Cloud Run decided the
 * instance was idle and recycled it, which is indistinguishable from a hang until the next
 * boot's startup recovery marks the interrupted job "failed" (`main.ts`'s
 * `recoverInterruptedState`). The scheduled sync solved this the same way (ADR-004 commitment
 * 1: a real Job, its own container, no request to outlive) — this brings admin-triggered syncs
 * in line with it.
 */
export class CloudRunSyncLauncher implements SyncLauncher {
  async launch(jobId: number, packageName: string): Promise<string> {
    if (!config.GCP_PROJECT || !config.GCP_REGION || !config.SYNC_JOB) {
      throw new Error("GCP_PROJECT, GCP_REGION and SYNC_JOB are required");
    }
    const tokenResponse = await fetch(
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      { headers: { "Metadata-Flavor": "Google" }, signal: AbortSignal.timeout(5_000) },
    );
    if (!tokenResponse.ok)
      throw new Error(`Failed to obtain GCP access token (${tokenResponse.status})`);
    const token = (await tokenResponse.json()) as { access_token: string };
    const jobName = `projects/${config.GCP_PROJECT}/locations/${config.GCP_REGION}/jobs/${config.SYNC_JOB}`;
    const response = await fetch(`https://run.googleapis.com/v2/${jobName}:run`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token.access_token}`,
        "Content-Type": "application/json",
      },
      // String(), not the bare number: sync_jobs.id is a plain SERIAL (unlike
      // vuln_backfill_jobs.id, BIGSERIAL, WAL-98's TYPE_STRING rejection), but the Cloud Run
      // Jobs API still type-checks container args as strings regardless of the column type.
      body: JSON.stringify({
        overrides: {
          containerOverrides: [{ args: ["--package", packageName, "--job-id", String(jobId)] }],
        },
      }),
      signal: AbortSignal.timeout(15_000),
    });
    if (!response.ok)
      throw new Error(`Cloud Run Job launch failed (${response.status}): ${await response.text()}`);
    const operation = (await response.json()) as { name?: string };
    return operation.name ?? jobName;
  }
}
