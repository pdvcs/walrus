import { Pool } from "pg";
import { ArtifactRow, ArtifactStatus } from "../../types/db.js";

export async function insertArtifact(
  pool: Pool,
  a: Pick<ArtifactRow, "version_id" | "os" | "arch" | "filename" | "upstream_url"> & {
    sync_job_id?: number | null;
    cooling_off_until?: Date | null;
  },
): Promise<ArtifactRow> {
  const { rows } = await pool.query<ArtifactRow>(
    `INSERT INTO artifacts (version_id, os, arch, filename, upstream_url, sync_job_id, cooling_off_until)
     VALUES ($1, $2, $3, $4, $5, $6, $7)
     ON CONFLICT (version_id, os, arch) DO UPDATE
       SET sync_job_id = EXCLUDED.sync_job_id
       WHERE artifacts.status IN ('pending', 'failed')
     RETURNING *`,
    [
      a.version_id,
      a.os,
      a.arch,
      a.filename,
      a.upstream_url,
      a.sync_job_id ?? null,
      a.cooling_off_until ?? null,
    ],
  );
  if (rows[0]) return rows[0];
  const existing = await getArtifact(pool, a.version_id, a.os, a.arch);
  return existing!;
}

export async function getArtifact(
  pool: Pool,
  versionId: number,
  os: string,
  arch: string,
): Promise<ArtifactRow | null> {
  const { rows } = await pool.query<ArtifactRow>(
    "SELECT * FROM artifacts WHERE version_id = $1 AND os = $2 AND arch = $3",
    [versionId, os, arch],
  );
  return rows[0] ?? null;
}

export async function getArtifactById(pool: Pool, id: number): Promise<ArtifactRow | null> {
  const { rows } = await pool.query<ArtifactRow>("SELECT * FROM artifacts WHERE id = $1", [id]);
  return rows[0] ?? null;
}

export interface ArtifactStatusUpdate {
  status: ArtifactStatus;
  gcs_path?: string | null;
  file_size?: number | null;
  checksum?: string | null;
  checksum_type?: string | null;
  error_message?: string | null;
  download_started_at?: Date | null;
  download_completed_at?: Date | null;
  removed_at?: Date | null;
}

export async function updateArtifactStatus(
  pool: Pool,
  id: number,
  update: ArtifactStatusUpdate,
): Promise<ArtifactRow | null> {
  const fields: string[] = ["status = $2"];
  const params: unknown[] = [id, update.status];

  const optional: Array<[keyof ArtifactStatusUpdate, string]> = [
    ["gcs_path", "gcs_path"],
    ["file_size", "file_size"],
    ["checksum", "checksum"],
    ["checksum_type", "checksum_type"],
    ["error_message", "error_message"],
    ["download_started_at", "download_started_at"],
    ["download_completed_at", "download_completed_at"],
    ["removed_at", "removed_at"],
  ];

  for (const [key, col] of optional) {
    if (key in update) {
      params.push(update[key]);
      fields.push(`${col} = $${params.length}`);
    }
  }

  const { rows } = await pool.query<ArtifactRow>(
    `UPDATE artifacts SET ${fields.join(", ")} WHERE id = $1 RETURNING *`,
    params,
  );
  return rows[0] ?? null;
}

export async function listArtifactsByStatus(
  pool: Pool,
  status: ArtifactStatus,
  limit = 100,
): Promise<ArtifactRow[]> {
  const { rows } = await pool.query<ArtifactRow>(
    "SELECT * FROM artifacts WHERE status = $1 ORDER BY created_at DESC LIMIT $2",
    [status, limit],
  );
  return rows;
}

export interface FailedArtifactRow extends ArtifactRow {
  package_name: string;
  version: string;
}

export async function listFailedArtifacts(
  pool: Pool,
  opts: { packageName?: string; limit?: number } = {},
): Promise<FailedArtifactRow[]> {
  const limit = opts.limit ?? 100;
  const conditions = ["a.status = 'failed'"];
  const params: unknown[] = [];

  if (opts.packageName) {
    params.push(opts.packageName);
    conditions.push(`v.package_name = $${params.length}`);
  }

  params.push(limit);
  const { rows } = await pool.query<FailedArtifactRow>(
    `SELECT a.*, v.package_name, v.version
     FROM artifacts a
     JOIN versions v ON a.version_id = v.id
     WHERE ${conditions.join(" AND ")}
     ORDER BY a.download_completed_at DESC NULLS LAST
     LIMIT $${params.length}`,
    params,
  );
  return rows;
}

export interface PendingArtifactRow extends ArtifactRow {
  package_name: string;
  version: string;
}

export async function listPendingArtifacts(
  pool: Pool,
  opts: { packageName?: string; limit?: number } = {},
): Promise<PendingArtifactRow[]> {
  const limit = opts.limit ?? 100;
  const conditions = ["a.status = 'pending'"];
  const params: unknown[] = [];

  if (opts.packageName) {
    params.push(opts.packageName);
    conditions.push(`v.package_name = $${params.length}`);
  }

  params.push(limit);
  const { rows } = await pool.query<PendingArtifactRow>(
    `SELECT a.*, v.package_name, v.version
     FROM artifacts a
     JOIN versions v ON a.version_id = v.id
     WHERE ${conditions.join(" AND ")}
     ORDER BY v.version_sort DESC, a.os, a.arch
     LIMIT $${params.length}`,
    params,
  );
  return rows;
}

export async function listArtifactsForVersion(
  pool: Pool,
  versionId: number,
): Promise<ArtifactRow[]> {
  const { rows } = await pool.query<ArtifactRow>(
    "SELECT * FROM artifacts WHERE version_id = $1 ORDER BY os, arch",
    [versionId],
  );
  return rows;
}
