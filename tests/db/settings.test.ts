import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import {
  deleteSetting,
  getSetting,
  listSettings,
  upsertSetting,
} from "../../src/db/queries/settings.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const NAME = "test_setting_key";

describe("settings", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM settings WHERE name LIKE 'test\\_%'`);
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM settings WHERE name LIKE 'test\\_%'`);
    await pool.end();
  });

  it("inserts, then replaces, reporting which happened", async () => {
    const first = await upsertSetting(pool, { name: NAME, value: "one", updated_by: "a" });
    expect(first.created).toBe(true);
    const second = await upsertSetting(pool, { name: NAME, value: "two", updated_by: "b" });
    expect(second.created).toBe(false);
    expect(second.setting.value).toBe("two");
    expect(second.setting.updated_by).toBe("b");
    expect(second.setting.updated_at.getTime()).toBeGreaterThanOrEqual(
      first.setting.updated_at.getTime(),
    );
    expect(second.setting.created_at).toEqual(first.setting.created_at);
  });

  it("round-trips multi-line text exactly", async () => {
    const pem = "-----BEGIN PUBLIC KEY-----\nMFkw\nEwYH\n-----END PUBLIC KEY-----";
    await upsertSetting(pool, { name: NAME, value: pem, updated_by: "a" });
    expect((await getSetting(pool, NAME))?.value).toBe(pem);
  });

  it("lists in name order and deletes", async () => {
    await upsertSetting(pool, { name: "test_b", value: "1", updated_by: "a" });
    await upsertSetting(pool, { name: "test_a", value: "1", updated_by: "a" });
    const names = (await listSettings(pool))
      .map((s) => s.name)
      .filter((n) => n.startsWith("test_"));
    expect(names).toEqual(["test_a", "test_b"]);
    expect(await deleteSetting(pool, "test_a")).toBe(true);
    expect(await deleteSetting(pool, "test_a")).toBe(false);
    expect(await getSetting(pool, "test_a")).toBeNull();
  });

  it("enforces name and value constraints in the database itself", async () => {
    await expect(
      pool.query(`INSERT INTO settings (name, value, updated_by) VALUES ('Bad-Name', 'x', 'a')`),
    ).rejects.toThrow();
    await expect(
      pool.query(`INSERT INTO settings (name, value, updated_by) VALUES ('test_blank', '  ', 'a')`),
    ).rejects.toThrow();
  });
});
