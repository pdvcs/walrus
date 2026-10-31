import { Queryable } from "../queryable.js";

export interface CoolingOffWaiverRow {
  id: number;
  package_name: string;
  version: string;
  reason: string;
  created_by: string;
  created_at: Date;
  revoked_at: Date | null;
}

export interface CreateCoolingOffWaiverInput {
  package_name: string;
  version: string;
  reason: string;
  created_by: string;
}

export async function createCoolingOffWaiver(
  q: Queryable,
  input: CreateCoolingOffWaiverInput,
): Promise<CoolingOffWaiverRow> {
  const { rows } = await q.query<CoolingOffWaiverRow>(
    `INSERT INTO cooling_off_waivers (package_name, version, reason, created_by)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [input.package_name, input.version.trim(), input.reason.trim(), input.created_by.trim()],
  );
  return rows[0];
}

export async function revokeCoolingOffWaiver(
  q: Queryable,
  id: number,
): Promise<CoolingOffWaiverRow | null> {
  const { rows } = await q.query<CoolingOffWaiverRow>(
    `UPDATE cooling_off_waivers
        SET revoked_at = now()
      WHERE id = $1 AND revoked_at IS NULL
      RETURNING *`,
    [id],
  );
  return rows[0] ?? null;
}

export async function listActiveCoolingOffWaivers(
  q: Queryable,
  packageName?: string,
): Promise<CoolingOffWaiverRow[]> {
  const { rows } = await q.query<CoolingOffWaiverRow>(
    `SELECT *
       FROM cooling_off_waivers
      WHERE revoked_at IS NULL
        AND ($1::text IS NULL OR package_name = $1)
      ORDER BY created_at DESC, id DESC`,
    [packageName ?? null],
  );
  return rows;
}

/** Versions of one package whose embargo an operator has waived. */
export async function listWaivedVersions(q: Queryable, packageName: string): Promise<Set<string>> {
  const rows = await listActiveCoolingOffWaivers(q, packageName);
  return new Set(rows.map((row) => row.version));
}
