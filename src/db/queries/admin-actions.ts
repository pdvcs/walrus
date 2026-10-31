import { Queryable } from "../queryable.js";

export interface AdminActionInput {
  action_type: string;
  package_name?: string | null;
  version?: string | null;
  details?: Record<string, unknown> | null;
  performed_by?: string | null;
}

export interface AdminActionRow {
  id: number;
  action_type: string;
  package_name: string | null;
  version: string | null;
  performed_by: string | null;
  details: Record<string, unknown> | null;
  created_at: Date;
}

export interface ListSuppressionAuditOptions {
  limit: number;
  beforeId?: number;
  cveId?: string;
}

/** Record an admin action in the audit log. */
export async function insertAdminAction(q: Queryable, input: AdminActionInput): Promise<void> {
  await q.query(
    `INSERT INTO admin_actions (action_type, package_name, version, performed_by, details)
     VALUES ($1, $2, $3, $4, $5)`,
    [
      input.action_type,
      input.package_name ?? null,
      input.version ?? null,
      input.performed_by ?? null,
      input.details ? JSON.stringify(input.details) : null,
    ],
  );
}

/**
 * Read the operator audit trail for CVE suppression lifecycle changes. The endpoint using this
 * query deliberately cannot expose unrelated admin actions, and every read is bounded/cursor
 * paginated so it remains safe as the shared audit table grows.
 */
export async function listSuppressionAuditActions(
  q: Queryable,
  opts: ListSuppressionAuditOptions,
): Promise<AdminActionRow[]> {
  const { rows } = await q.query<AdminActionRow>(
    `SELECT id, action_type, package_name, version, performed_by, details, created_at
       FROM admin_actions
      WHERE action_type = ANY($1::text[])
        AND ($2::integer IS NULL OR id < $2)
        AND ($3::text IS NULL OR details->>'cve_id' = $3)
      ORDER BY id DESC
      LIMIT $4`,
    [
      ["cve-suppression-created", "cve-suppression-revoked"],
      opts.beforeId ?? null,
      opts.cveId ?? null,
      opts.limit,
    ],
  );
  return rows;
}
