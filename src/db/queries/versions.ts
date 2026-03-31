import { Pool } from "pg";
import { VersionRow } from "../../types/db.js";

export async function insertVersion(
  pool: Pool,
  v: Omit<VersionRow, "id" | "discovered_at">,
): Promise<VersionRow> {
  const { rows } = await pool.query<VersionRow>(
    `INSERT INTO versions (package_name, version, version_group, is_lts, version_sort)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (package_name, version) DO NOTHING
     RETURNING *`,
    [v.package_name, v.version, v.version_group, v.is_lts, v.version_sort],
  );
  if (rows[0]) return rows[0];
  // Already exists — fetch and return it
  const existing = await getVersion(pool, v.package_name, v.version);
  return existing!;
}

export async function getVersion(
  pool: Pool,
  packageName: string,
  version: string,
): Promise<VersionRow | null> {
  const { rows } = await pool.query<VersionRow>(
    "SELECT * FROM versions WHERE package_name = $1 AND version = $2",
    [packageName, version],
  );
  return rows[0] ?? null;
}

export interface ListVersionsOpts {
  group?: string;
  lts?: boolean;
}

export async function listVersions(
  pool: Pool,
  packageName: string,
  opts: ListVersionsOpts = {},
): Promise<VersionRow[]> {
  const conditions: string[] = ["package_name = $1"];
  const params: unknown[] = [packageName];

  if (opts.group !== undefined) {
    params.push(opts.group);
    conditions.push(`version_group = $${params.length}`);
  }
  if (opts.lts !== undefined) {
    params.push(opts.lts);
    conditions.push(`is_lts = $${params.length}`);
  }

  const { rows } = await pool.query<VersionRow>(
    `SELECT * FROM versions WHERE ${conditions.join(" AND ")} ORDER BY version_sort DESC`,
    params,
  );
  return rows;
}

export async function getLatestVersionInGroup(
  pool: Pool,
  packageName: string,
  group: string,
  opts: { os?: string; arch?: string } = {},
): Promise<VersionRow | null> {
  const params: unknown[] = [packageName, group];
  const artifactConditions: string[] = ["a.status = 'available'"];

  if (opts.os) {
    params.push(opts.os);
    artifactConditions.push(`a.os = $${params.length}`);
  }
  if (opts.arch) {
    params.push(opts.arch);
    artifactConditions.push(`a.arch = $${params.length}`);
  }

  const { rows } = await pool.query<VersionRow>(
    `SELECT v.* FROM versions v
     WHERE v.package_name = $1 AND v.version_group = $2
       AND EXISTS (
         SELECT 1 FROM artifacts a
         WHERE a.version_id = v.id AND ${artifactConditions.join(" AND ")}
       )
     ORDER BY v.version_sort DESC
     LIMIT 1`,
    params,
  );
  return rows[0] ?? null;
}

export async function listVersionGroups(pool: Pool, packageName: string): Promise<string[]> {
  const { rows } = await pool.query<{ version_group: string }>(
    `SELECT version_group, MAX(version_sort) AS max_sort
     FROM versions
     WHERE package_name = $1
     GROUP BY version_group
     ORDER BY max_sort DESC`,
    [packageName],
  );
  return rows.map((r) => r.version_group);
}

export interface VersionGroupSummary {
  group: string;
  is_lts: boolean;
  latest_available: string | null;
}

export async function listVersionGroupSummaries(
  pool: Pool,
  packageName: string,
  opts: { os?: string; arch?: string } = {},
): Promise<VersionGroupSummary[]> {
  const params: unknown[] = [packageName];
  const artifactConditions: string[] = ["a.status = 'available'"];

  if (opts.os) {
    params.push(opts.os);
    artifactConditions.push(`a.os = $${params.length}`);
  }
  if (opts.arch) {
    params.push(opts.arch);
    artifactConditions.push(`a.arch = $${params.length}`);
  }

  const artifactWhere = artifactConditions.join(" AND ");

  const { rows } = await pool.query<VersionGroupSummary>(
    `SELECT
       v.version_group                    AS group,
       bool_or(v.is_lts)                  AS is_lts,
       (
         SELECT v2.version
         FROM versions v2
         WHERE v2.package_name = v.package_name
           AND v2.version_group = v.version_group
           AND EXISTS (
             SELECT 1 FROM artifacts a
             WHERE a.version_id = v2.id AND ${artifactWhere}
           )
         ORDER BY v2.version_sort DESC
         LIMIT 1
       )                                  AS latest_available
     FROM versions v
     WHERE v.package_name = $1
     GROUP BY v.package_name, v.version_group
     HAVING EXISTS (
       SELECT 1 FROM versions v3
       JOIN artifacts a ON a.version_id = v3.id
       WHERE v3.package_name = v.package_name
         AND v3.version_group = v.version_group
         AND ${artifactWhere}
     )
     ORDER BY MAX(v.version_sort) DESC`,
    params,
  );
  return rows;
}

/**
 * Returns the highest version_sort among versions that have at least one available artifact.
 * Used as the cooling-off threshold: versions strictly above this are considered newly released.
 * Returns null when no available artifacts exist yet (bootstrap / fresh install).
 */
export async function getMaxAvailableVersionSort(
  pool: Pool,
  packageName: string,
): Promise<string | null> {
  const { rows } = await pool.query<{ max_sort: string | null }>(
    `SELECT MAX(v.version_sort) AS max_sort
     FROM versions v
     WHERE v.package_name = $1
       AND EXISTS (
         SELECT 1 FROM artifacts a
         WHERE a.version_id = v.id AND a.status = 'available'
       )`,
    [packageName],
  );
  return rows[0]?.max_sort ?? null;
}

export interface GroupArtifactRow {
  artifact_id: number;
  version: string;
  os: string;
  arch: string;
  gcs_path: string | null;
}

export async function listArtifactsInGroup(
  pool: Pool,
  packageName: string,
  group: string,
): Promise<GroupArtifactRow[]> {
  const { rows } = await pool.query<GroupArtifactRow>(
    `SELECT a.id AS artifact_id, v.version, a.os, a.arch, a.gcs_path
     FROM versions v
     JOIN artifacts a ON a.version_id = v.id
     WHERE v.package_name = $1 AND v.version_group = $2`,
    [packageName, group],
  );
  return rows;
}

export async function deleteVersionGroup(
  pool: Pool,
  packageName: string,
  group: string,
): Promise<{ versionsDeleted: number; artifactsDeleted: number }> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rowCount: artifactsDeleted } = await client.query(
      `DELETE FROM artifacts
       WHERE version_id IN (
         SELECT id FROM versions WHERE package_name = $1 AND version_group = $2
       )`,
      [packageName, group],
    );
    const { rowCount: versionsDeleted } = await client.query(
      "DELETE FROM versions WHERE package_name = $1 AND version_group = $2",
      [packageName, group],
    );
    await client.query("COMMIT");
    return { versionsDeleted: versionsDeleted ?? 0, artifactsDeleted: artifactsDeleted ?? 0 };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function listAllArtifactsForPackage(
  pool: Pool,
  packageName: string,
): Promise<GroupArtifactRow[]> {
  const { rows } = await pool.query<GroupArtifactRow>(
    `SELECT a.id AS artifact_id, v.version, a.os, a.arch, a.gcs_path
     FROM versions v
     JOIN artifacts a ON a.version_id = v.id
     WHERE v.package_name = $1`,
    [packageName],
  );
  return rows;
}

export async function deleteAllVersionsForPackage(
  pool: Pool,
  packageName: string,
): Promise<{ versionsDeleted: number; artifactsDeleted: number }> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const { rowCount: artifactsDeleted } = await client.query(
      `DELETE FROM artifacts
       WHERE version_id IN (SELECT id FROM versions WHERE package_name = $1)`,
      [packageName],
    );
    const { rowCount: versionsDeleted } = await client.query(
      "DELETE FROM versions WHERE package_name = $1",
      [packageName],
    );
    await client.query("COMMIT");
    return { versionsDeleted: versionsDeleted ?? 0, artifactsDeleted: artifactsDeleted ?? 0 };
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

export async function listVersionsOlderThanInGroup(
  pool: Pool,
  packageName: string,
  group: string,
  keepCount: number,
): Promise<VersionRow[]> {
  const { rows } = await pool.query<VersionRow>(
    `SELECT * FROM versions
     WHERE package_name = $1 AND version_group = $2
     ORDER BY version_sort DESC
     OFFSET $3`,
    [packageName, group, keepCount],
  );
  return rows;
}
