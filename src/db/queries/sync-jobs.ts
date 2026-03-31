import { Pool } from "pg";
import { SyncJobRow, SyncJobStatus, SyncJobTrigger } from "../../types/db.js";

export interface ArtifactSummary {
  id: number;
  version: string;
  version_sort: string;
  os: string;
  arch: string;
  filename: string;
  status: string;
  error_message: string | null;
  download_started_at: Date | null;
  download_completed_at: Date | null;
  created_at: Date;
}

export interface JobDetail {
  job: SyncJobRow;
  artifacts: ArtifactSummary[];
  elapsed_ms: number;
  cooling_off_days?: number;
  /** Highest version_sort with an available artifact at display time; null = no baseline yet. */
  cooling_off_threshold: string | null;
}

export async function createSyncJob(
  pool: Pool,
  packageName: string,
  triggerType: SyncJobTrigger,
): Promise<SyncJobRow> {
  const { rows } = await pool.query<SyncJobRow>(
    `INSERT INTO sync_jobs (package_name, trigger_type)
     VALUES ($1, $2)
     RETURNING *`,
    [packageName, triggerType],
  );
  return rows[0];
}

export interface SyncJobUpdate {
  status?: SyncJobStatus;
  versions_found?: number;
  artifacts_queued?: number;
  artifacts_downloaded?: number;
  artifacts_failed?: number;
  error_message?: string | null;
  completed_at?: Date | null;
}

export async function updateSyncJob(
  pool: Pool,
  id: number,
  update: SyncJobUpdate,
): Promise<SyncJobRow | null> {
  const fields: string[] = [];
  const params: unknown[] = [id];

  const optional: Array<[keyof SyncJobUpdate, string]> = [
    ["status", "status"],
    ["versions_found", "versions_found"],
    ["artifacts_queued", "artifacts_queued"],
    ["artifacts_downloaded", "artifacts_downloaded"],
    ["artifacts_failed", "artifacts_failed"],
    ["error_message", "error_message"],
    ["completed_at", "completed_at"],
  ];

  for (const [key, col] of optional) {
    if (key in update) {
      params.push(update[key]);
      fields.push(`${col} = $${params.length}`);
    }
  }

  if (fields.length === 0) return null;

  const { rows } = await pool.query<SyncJobRow>(
    `UPDATE sync_jobs SET ${fields.join(", ")} WHERE id = $1 RETURNING *`,
    params,
  );
  return rows[0] ?? null;
}

export async function getSyncJob(pool: Pool, id: number): Promise<SyncJobRow | null> {
  const { rows } = await pool.query<SyncJobRow>("SELECT * FROM sync_jobs WHERE id = $1", [id]);
  return rows[0] ?? null;
}

export async function getRecentSyncJob(
  pool: Pool,
  packageName: string,
  withinMinutes: number,
): Promise<SyncJobRow | null> {
  const { rows } = await pool.query<SyncJobRow>(
    `SELECT * FROM sync_jobs
     WHERE package_name = $1
       AND status = 'completed'
       AND completed_at > now() - interval '1 minute' * $2
     ORDER BY completed_at DESC
     LIMIT 1`,
    [packageName, withinMinutes],
  );
  return rows[0] ?? null;
}

export interface ListSyncJobsOpts {
  packageName?: string;
  status?: SyncJobStatus;
  limit?: number;
}

export async function incrementJobCounters(
  pool: Pool,
  jobId: number,
  delta: { downloaded?: number; failed?: number },
): Promise<void> {
  const parts: string[] = [];
  const params: unknown[] = [jobId];

  if (delta.downloaded) {
    params.push(delta.downloaded);
    parts.push(`artifacts_downloaded = artifacts_downloaded + $${params.length}`);
  }
  if (delta.failed) {
    params.push(delta.failed);
    parts.push(`artifacts_failed = artifacts_failed + $${params.length}`);
  }

  if (parts.length === 0) return;
  await pool.query(`UPDATE sync_jobs SET ${parts.join(", ")} WHERE id = $1`, params);
}

export async function getJobWithArtifacts(pool: Pool, id: number): Promise<JobDetail | null> {
  const jobRes = await pool.query<SyncJobRow>("SELECT * FROM sync_jobs WHERE id = $1", [id]);
  const job = jobRes.rows[0];
  if (!job) return null;

  const artifactRes = await pool.query<ArtifactSummary>(
    `SELECT a.id, v.version, v.version_sort, a.os, a.arch, a.filename,
            a.status, a.error_message,
            a.download_started_at, a.download_completed_at, a.created_at
     FROM artifacts a
     JOIN versions v ON a.version_id = v.id
     WHERE a.sync_job_id = $1
     ORDER BY v.version_sort DESC, a.os, a.arch`,
    [id],
  );

  const endMs = job.completed_at ? job.completed_at.getTime() : Date.now();
  const elapsed_ms = endMs - job.started_at.getTime();

  return { job, artifacts: artifactRes.rows, elapsed_ms, cooling_off_threshold: null };
}

export async function listSyncJobs(pool: Pool, opts: ListSyncJobsOpts = {}): Promise<SyncJobRow[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (opts.packageName) {
    params.push(opts.packageName);
    conditions.push(`package_name = $${params.length}`);
  }
  if (opts.status) {
    params.push(opts.status);
    conditions.push(`status = $${params.length}`);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const limit = opts.limit ?? 50;
  params.push(limit);

  const { rows } = await pool.query<SyncJobRow>(
    `SELECT * FROM sync_jobs ${where} ORDER BY started_at DESC LIMIT $${params.length}`,
    params,
  );
  return rows;
}
