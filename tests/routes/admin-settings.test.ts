import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAdminSettingsRouter } from "../../src/routes/admin-settings.js";
import type { SettingRow } from "../../src/db/queries/settings.js";

function row(overrides: Partial<SettingRow> = {}): SettingRow {
  return {
    name: "registry_public_key",
    value: "-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
    updated_by: "admin",
    created_at: new Date("2026-01-01T00:00:00Z"),
    updated_at: new Date("2026-01-02T03:04:05Z"),
    ...overrides,
  };
}

function setup(settings: SettingRow[] = []) {
  const deps = {
    listSettings: vi.fn().mockResolvedValue(settings),
    upsertSetting: vi
      .fn()
      .mockImplementation(async (i) => ({ setting: row({ ...i }), created: true })),
    deleteSetting: vi.fn().mockResolvedValue(true),
    logAdminAction: vi.fn().mockResolvedValue(undefined),
  };
  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    req.auth = { kind: "bearer", subject: "admin" } as never;
    next();
  });
  app.use("/admin/v1", createAdminSettingsRouter(deps, ""));
  return { app, deps };
}

describe("admin settings routes", () => {
  it("renders existing settings, escaping names and values", async () => {
    const { app } = setup([row({ value: "<script>alert(1)</script>" })]);
    const res = await request(app).get("/admin/v1/settings");
    expect(res.status).toBe(200);
    expect(res.text).toContain("registry_public_key");
    expect(res.text).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
    expect(res.text).not.toContain("<script>alert(1)</script>");
  });

  it("shows an empty state with the add form", async () => {
    const { app } = setup([]);
    const res = await request(app).get("/admin/v1/settings");
    expect(res.text).toContain("No settings yet");
    expect(res.text).toContain('id="setting-form"');
  });

  it("lists settings as JSON", async () => {
    const { app } = setup([row()]);
    const res = await request(app).get("/admin/v1/settings.json");
    expect(res.status).toBe(200);
    expect(res.body.settings[0].name).toBe("registry_public_key");
  });

  it("creates a setting, trimming the value and auditing without the value", async () => {
    const { app, deps } = setup();
    const res = await request(app)
      .put("/admin/v1/settings/registry_public_key")
      .send({ value: "  KEY\n" });
    expect(res.status).toBe(201);
    expect(deps.upsertSetting).toHaveBeenCalledWith({
      name: "registry_public_key",
      value: "KEY",
      updated_by: "admin",
    });
    expect(deps.logAdminAction).toHaveBeenCalledWith(
      "setting-created",
      { name: "registry_public_key" },
      "admin",
    );
  });

  it("answers 200 and audits an update when the name already existed", async () => {
    const { app, deps } = setup();
    deps.upsertSetting.mockResolvedValueOnce({ setting: row(), created: false });
    const res = await request(app)
      .put("/admin/v1/settings/registry_public_key")
      .send({ value: "x" });
    expect(res.status).toBe(200);
    expect(deps.logAdminAction).toHaveBeenCalledWith(
      "setting-updated",
      { name: "registry_public_key" },
      "admin",
    );
  });

  it.each(["Bad", "1abc", "has-dash", "a".repeat(65)])("rejects name %s", async (name) => {
    const { app, deps } = setup();
    const res = await request(app).put(`/admin/v1/settings/${name}`).send({ value: "x" });
    expect(res.status).toBe(400);
    expect(deps.upsertSetting).not.toHaveBeenCalled();
  });

  it.each([{}, { value: 5 }, { value: "   " }, { value: "x".repeat(65537) }])(
    "rejects value %j",
    async (body) => {
      const { app, deps } = setup();
      const res = await request(app).put("/admin/v1/settings/ok_name").send(body);
      expect(res.status).toBe(400);
      expect(deps.upsertSetting).not.toHaveBeenCalled();
    },
  );

  it("deletes a setting and audits it", async () => {
    const { app, deps } = setup();
    const res = await request(app).delete("/admin/v1/settings/registry_public_key");
    expect(res.status).toBe(200);
    expect(deps.logAdminAction).toHaveBeenCalledWith(
      "setting-deleted",
      { name: "registry_public_key" },
      "admin",
    );
  });

  it("404s when deleting a missing setting, without auditing", async () => {
    const { app, deps } = setup();
    deps.deleteSetting.mockResolvedValueOnce(false);
    const res = await request(app).delete("/admin/v1/settings/nope");
    expect(res.status).toBe(404);
    expect(deps.logAdminAction).not.toHaveBeenCalled();
  });
});
