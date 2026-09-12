import { Queryable } from "../queryable.js";

export type VulnBackfillJobStatus = "queued" | "running" | "succeeded" | "failed";

export interface VulnBackfillJobRow {
  id: string;
  status: VulnBackfillJobStatus;
  since_date: string | null;
  /** null = every tracked CPE pair; otherwise the single package to backfill. */
  package_name: string | null;
  cpe_pairs_total: number;
  cpe_pairs_done: number;
  error_message: string | null;
  execution_name: string | null;
  started_at: Date | null;
  finished_at: Date | null;
  created_at: Date;
}

/**
 * `since_date` is a DATE column, and pg parses DATE into a JS `Date` — so a row straight from the
 * driver does not match `since_date: string` above, however cleanly it type-checks. Same class of
 * mismatch as the BIGINT `id` documented in vuln/backfill-launcher.ts, and it bit harder: the only
 * consumer (`runVulnBackfillJob`) hands the value to `backfillNvd`, which requires YYYY-MM-DD and
 * validates it, so an uncoerced Date arrived as "Mon Jan 01 2024 00:00:00 GMT+0000" and failed
 * every since-bounded backfill at the first step — over the API, in dev and in Cloud Run alike,
 * since both launchers run this same path.
 *
 * Coerced here rather than at the consumer so the declared type is true for every caller.
 */
function normalizeJob(row: VulnBackfillJobRow): VulnBackfillJobRow {
  // db/client.ts installs a global BIGINT parser, so `id` arrives as a JS number at runtime even
  // though this type says string. Coerce so callers get what was promised — the admin HTML
  // renderer escapes the id and a number has no `.replace` (WAL-121).
  const id = String(row.id);
  const since: unknown = row.since_date;
  if (!(since instanceof Date)) return { ...row, id };
  // Local getters, not toISOString(): pg returns a DATE as midnight *local* time, so in any
  // negative-offset zone the UTC form of that instant lands on the previous calendar day and
  // would silently shift the window back 24 hours.
  const month = String(since.getMonth() + 1).padStart(2, "0");
  const day = String(since.getDate()).padStart(2, "0");
  return { ...row, id, since_date: `${since.getFullYear()}-${month}-${day}` };
}

export async function createVulnBackfillJob(
  q: Queryable,
  since?: string,
  packageName?: string,
): Promise<VulnBackfillJobRow> {
  const { rows } = await q.query<VulnBackfillJobRow>(
    `INSERT INTO vuln_backfill_jobs (since_date, package_name) VALUES ($1, $2) RETURNING *`,
    [since ?? null, packageName ?? null],
  );
  return normalizeJob(rows[0]);
}

export async function getVulnBackfillJob(
  q: Queryable,
  id: string,
): Promise<VulnBackfillJobRow | null> {
  const { rows } = await q.query<VulnBackfillJobRow>(
    `SELECT * FROM vuln_backfill_jobs WHERE id = $1`,
    [id],
  );
  return rows[0] ? normalizeJob(rows[0]) : null;
}

export interface ListVulnBackfillJobsOpts {
  status?: VulnBackfillJobStatus;
  limit?: number;
  offset?: number;
}

/**
 * Newest-first listing for the admin Vuln Jobs page (WAL-121). Mirrors `listSyncJobs`: the
 * filters are optional and the ordering is fixed, so the HTML page and the JSON API read the
 * same rows through one query.
 */
export async function listVulnBackfillJobs(
  q: Queryable,
  opts: ListVulnBackfillJobsOpts = {},
): Promise<VulnBackfillJobRow[]> {
  const values: unknown[] = [];
  const where = opts.status ? `WHERE status = $${values.push(opts.status)}` : "";
  let sql = `SELECT * FROM vuln_backfill_jobs ${where} ORDER BY created_at DESC`;
  if (opts.limit !== undefined) sql += ` LIMIT $${values.push(opts.limit)}`;
  if (opts.offset !== undefined) sql += ` OFFSET $${values.push(opts.offset)}`;
  const { rows } = await q.query<VulnBackfillJobRow>(sql, values);
  return rows.map(normalizeJob);
}

export async function getActiveVulnBackfillJob(q: Queryable): Promise<VulnBackfillJobRow | null> {
  const { rows } = await q.query<VulnBackfillJobRow>(
    `SELECT * FROM vuln_backfill_jobs WHERE status IN ('queued', 'running') ORDER BY created_at LIMIT 1`,
  );
  return rows[0] ? normalizeJob(rows[0]) : null;
}

export async function updateVulnBackfillJob(
  q: Queryable,
  id: string,
  update: Partial<
    Pick<
      VulnBackfillJobRow,
      "status" | "cpe_pairs_total" | "cpe_pairs_done" | "error_message" | "execution_name"
    >
  > & { started_at?: Date; finished_at?: Date },
): Promise<void> {
  const entries = Object.entries(update);
  if (entries.length === 0) return;
  const values: unknown[] = [id];
  const sets = entries.map(([column, value]) => {
    values.push(value);
    return `${column} = $${values.length}`;
  });
  await q.query(`UPDATE vuln_backfill_jobs SET ${sets.join(", ")} WHERE id = $1`, values);
}
