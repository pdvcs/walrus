import { Pool } from "pg";

export interface AdminActionInput {
  action_type: string;
  package_name?: string | null;
  version?: string | null;
  details?: Record<string, unknown> | null;
  performed_by?: string | null;
}

/** Record an admin action in the audit log. */
export async function insertAdminAction(pool: Pool, input: AdminActionInput): Promise<void> {
  await pool.query(
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
