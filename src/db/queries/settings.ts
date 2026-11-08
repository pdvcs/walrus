import { Queryable } from "../queryable.js";

export interface SettingRow {
  name: string;
  value: string;
  updated_by: string;
  created_at: Date;
  updated_at: Date;
}

export const SETTING_NAME_PATTERN = /^[a-z][a-z0-9_]*$/;
export const SETTING_NAME_MAX_LENGTH = 64;
export const SETTING_VALUE_MAX_LENGTH = 65536;

export async function listSettings(q: Queryable): Promise<SettingRow[]> {
  const { rows } = await q.query<SettingRow>(`SELECT * FROM settings ORDER BY name`);
  return rows;
}

/** The value of one setting, or null when it has never been set. For code that consumes settings. */
export async function getSetting(q: Queryable, name: string): Promise<SettingRow | null> {
  const { rows } = await q.query<SettingRow>(`SELECT * FROM settings WHERE name = $1`, [name]);
  return rows[0] ?? null;
}

/**
 * Create or replace a setting. `created` reports which, via Postgres's `xmax = 0` marker for a
 * freshly inserted row, so the audit trail can tell an add from an overwrite without a second
 * round trip (and without a read-then-write race).
 */
export async function upsertSetting(
  q: Queryable,
  input: { name: string; value: string; updated_by: string },
): Promise<{ setting: SettingRow; created: boolean }> {
  const { rows } = await q.query<SettingRow & { created: boolean }>(
    `INSERT INTO settings (name, value, updated_by)
     VALUES ($1, $2, $3)
     ON CONFLICT (name) DO UPDATE
        SET value = EXCLUDED.value,
            updated_by = EXCLUDED.updated_by,
            updated_at = now()
     RETURNING *, (xmax = 0) AS created`,
    [input.name, input.value, input.updated_by.trim()],
  );
  const { created, ...setting } = rows[0];
  return { setting, created };
}

export async function deleteSetting(q: Queryable, name: string): Promise<boolean> {
  const { rowCount } = await q.query(`DELETE FROM settings WHERE name = $1`, [name]);
  return (rowCount ?? 0) > 0;
}
