import { Queryable } from "../queryable.js";

export type VulnBackfillJobStatus = "queued" | "running" | "succeeded" | "failed";

export interface VulnBackfillJobRow {
  id: string;
  status: VulnBackfillJobStatus;
  since_date: string | null;
  cpe_pairs_total: number;
  cpe_pairs_done: number;
  error_message: string | null;
  execution_name: string | null;
  started_at: Date | null;
  finished_at: Date | null;
  created_at: Date;
}

export async function createVulnBackfillJob(
  q: Queryable,
  since?: string,
): Promise<VulnBackfillJobRow> {
  const { rows } = await q.query<VulnBackfillJobRow>(
    `INSERT INTO vuln_backfill_jobs (since_date) VALUES ($1) RETURNING *`,
    [since ?? null],
  );
  return rows[0];
}

export async function getVulnBackfillJob(
  q: Queryable,
  id: string,
): Promise<VulnBackfillJobRow | null> {
  const { rows } = await q.query<VulnBackfillJobRow>(
    `SELECT * FROM vuln_backfill_jobs WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

export async function getActiveVulnBackfillJob(q: Queryable): Promise<VulnBackfillJobRow | null> {
  const { rows } = await q.query<VulnBackfillJobRow>(
    `SELECT * FROM vuln_backfill_jobs WHERE status IN ('queued', 'running') ORDER BY created_at LIMIT 1`,
  );
  return rows[0] ?? null;
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
