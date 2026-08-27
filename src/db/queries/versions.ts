import { Pool } from "pg";
import { VersionRow } from "../../types/db.js";
import { generateSortKey } from "../../common/version-utils.js";

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
  const versions = await listAvailableVersionsInGroup(pool, packageName, group, opts);
  return versions[0] ?? null;
}

/** All versions in a group with a matching available artifact, newest first. */
export async function listAvailableVersionsInGroup(
  pool: Pool,
  packageName: string,
  group: string,
  opts: { os?: string; arch?: string } = {},
): Promise<VersionRow[]> {
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
     ORDER BY v.version_sort DESC`,
    params,
  );
  return rows;
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

export interface VersionGroupWithLts {
  version_group: string;
  is_lts: boolean;
}

/**
 * Every group for a package, newest first, regardless of whether anything in it is servable.
 *
 * The groups endpoint pairs this with the available-only candidate list so a group whose versions
 * are all embargoed or CVE-blocked still appears, carrying `latest_available: null`, rather than
 * vanishing from the listing entirely.
 */
export async function listVersionGroupsWithLts(
  pool: Pool,
  packageName: string,
): Promise<VersionGroupWithLts[]> {
  const { rows } = await pool.query<{ version_group: string; is_lts: boolean }>(
    `SELECT version_group, bool_or(is_lts) AS is_lts, MAX(version_sort) AS max_sort
     FROM versions
     WHERE package_name = $1
     GROUP BY version_group
     ORDER BY max_sort DESC`,
    [packageName],
  );
  return rows.map((r) => ({ version_group: r.version_group, is_lts: r.is_lts }));
}

/**
 * The soonest moment a currently-embargoed artifact in this group becomes servable, or null when
 * the group has none. Lets the latest endpoint answer "temporarily withheld, come back at X"
 * instead of reporting an embargo as a plain 404.
 */
export async function getEarliestCoolingOffInGroup(
  pool: Pool,
  packageName: string,
  group: string,
  opts: { os?: string; arch?: string } = {},
): Promise<Date | null> {
  const params: unknown[] = [packageName, group];
  const conditions: string[] = ["a.cooling_off_until > now()"];

  if (opts.os) {
    params.push(opts.os);
    conditions.push(`a.os = $${params.length}`);
  }
  if (opts.arch) {
    params.push(opts.arch);
    conditions.push(`a.arch = $${params.length}`);
  }

  const { rows } = await pool.query<{ earliest: Date | null }>(
    `SELECT MIN(a.cooling_off_until) AS earliest
     FROM artifacts a
     JOIN versions v ON v.id = a.version_id
     WHERE v.package_name = $1 AND v.version_group = $2 AND ${conditions.join(" AND ")}`,
    params,
  );
  return rows[0]?.earliest ?? null;
}

export interface GroupVersionRow {
  version: string;
  version_group: string;
  is_lts: boolean;
}

/**
 * All versions with at least one matching available artifact, newest first.
 * Candidate list for the groups endpoint: the per-group "latest free of
 * critical CVEs" selection happens in TS (summarizeGroupsWithVulnGate), where
 * the CVE range-matching core lives. Ordering by version_sort DESC means the
 * first row seen for each group is its newest version, so first-appearance
 * group order equals ordering groups by max version_sort.
 */
export async function listAvailableVersionsByGroup(
  pool: Pool,
  packageName: string,
  opts: { os?: string; arch?: string } = {},
): Promise<GroupVersionRow[]> {
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

  const { rows } = await pool.query<GroupVersionRow>(
    `SELECT v.version, v.version_group, v.is_lts
     FROM versions v
     WHERE v.package_name = $1
       AND EXISTS (
         SELECT 1 FROM artifacts a
         WHERE a.version_id = v.id AND ${artifactConditions.join(" AND ")}
       )
     ORDER BY v.version_sort DESC`,
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

/**
 * Versions in a group beyond the newest `keepCount`, i.e. the ones retention should prune.
 *
 * With `exemptEmbargoed` (the default), versions still inside their release embargo are neither
 * returned nor counted towards `keepCount`: keepCount is a quota of *servable* versions, so a
 * cooling-off release must not displace the older version users are still downloading. Pass false
 * to prune a group wholesale, where the embargo is irrelevant because the group itself is going.
 */
export async function listVersionsOlderThanInGroup(
  pool: Pool,
  packageName: string,
  group: string,
  keepCount: number,
  exemptEmbargoed = true,
): Promise<VersionRow[]> {
  const embargoFilter = exemptEmbargoed
    ? `AND NOT EXISTS (
         SELECT 1 FROM artifacts a
         WHERE a.version_id = v.id AND a.cooling_off_until > now()
       )`
    : "";

  const { rows } = await pool.query<VersionRow>(
    `SELECT v.* FROM versions v
     WHERE v.package_name = $1 AND v.version_group = $2
     ${embargoFilter}
     ORDER BY v.version_sort DESC
     OFFSET $3`,
    [packageName, group, keepCount],
  );
  return rows;
}

/**
 * Reassert `version_sort` from `version` for every row, using the current sort-key algorithm.
 *
 * `version_sort` is derived data, but `insertVersion` is `ON CONFLICT DO NOTHING`, so a row is
 * keyed once at discovery and never re-keyed. A change to `generateSortKey` would therefore
 * leave existing rows ordered by the retired scheme indefinitely — and production has no shell
 * to run a fixup script from. Recomputing at boot keeps the stored column honest without a
 * hand-written SQL copy of the padding rules, which would only drift from the real one.
 *
 * Returns the number of rows corrected. Steady state is 0; a non-zero count means the algorithm
 * moved under existing data and is worth a log line.
 */
export async function resyncVersionSortKeys(pool: Pool): Promise<number> {
  const { rows } = await pool.query<{ id: number; version: string; version_sort: string }>(
    "SELECT id, version, version_sort FROM versions",
  );

  const ids: number[] = [];
  const sorts: string[] = [];
  for (const row of rows) {
    const expected = generateSortKey(row.version);
    if (expected !== row.version_sort) {
      ids.push(row.id);
      sorts.push(expected);
    }
  }
  if (ids.length === 0) return 0;

  await pool.query(
    `UPDATE versions AS v SET version_sort = u.version_sort
     FROM unnest($1::int[], $2::text[]) AS u(id, version_sort)
     WHERE v.id = u.id`,
    [ids, sorts],
  );
  return ids.length;
}
