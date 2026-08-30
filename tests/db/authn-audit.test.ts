import express from "express";
import { Pool } from "pg";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createAdminRoster } from "../../src/authn/admins.js";
import { createAuthAuditSinks } from "../../src/authn/audit.js";
import { installOperatorAuth } from "../../src/authn/operator.js";
import type { OperatorAuthRuntime } from "../../src/authn/runtime.js";
import { runMigrations } from "../../src/db/client.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

describe("authentication audit persistence", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await pool.query("DELETE FROM admin_actions WHERE action_type = 'operator-login'");
  });

  afterAll(async () => {
    await pool.query("DELETE FROM admin_actions WHERE action_type = 'operator-login'");
    await pool.end();
  });

  it("durably audits successful and unsuccessful login outcomes without credentials", async () => {
    const runtime: OperatorAuthRuntime = {
      provider: {
        name: "audit-fixture",
        apiVersion: 1,
        authenticate: async ({ username, password }) => {
          if (username === "unavailable") return { ok: false, reason: "unavailable" };
          if (password !== "correct") return { ok: false, reason: "invalid_credentials" };
          return { ok: true, subject: username };
        },
      },
      roster: createAdminRoster(["admin"], "exact"),
      sessions: {
        currentKey: Buffer.from("01234567890123456789012345678901"),
        ttlSeconds: 120,
        maxSeconds: 480,
        epoch: 1,
      },
      keyFingerprint: "12345678",
      nodeEnv: "test",
      minimumLoginMs: 0,
      auditLogin: createAuthAuditSinks(pool).auditLogin,
    };
    const router = express.Router();
    installOperatorAuth(router, runtime);
    const app = express().set("trust proxy", 1).use(express.json()).use("/admin/v1", router);

    const attempts = [
      { username: "admin", password: "correct", ip: "203.0.113.1", status: 200 },
      { username: "admin", password: "wrong-password", ip: "203.0.113.2", status: 401 },
      { username: "outsider", password: "correct", ip: "203.0.113.3", status: 403 },
      { username: "unavailable", password: "anything", ip: "203.0.113.4", status: 503 },
    ];
    for (const attempt of attempts) {
      await request(app)
        .post("/admin/v1/login")
        .set("x-forwarded-for", attempt.ip)
        .send({ username: attempt.username, password: attempt.password })
        .expect(attempt.status);
    }

    const { rows } = await pool.query<{
      performed_by: string;
      details: Record<string, unknown>;
    }>(
      `SELECT performed_by, details
         FROM admin_actions
        WHERE action_type = 'operator-login'
        ORDER BY id`,
    );
    expect(rows.map(({ details }) => details.outcome)).toEqual([
      "success",
      "invalid_credentials",
      "forbidden",
      "unavailable",
    ]);
    expect(rows.map(({ performed_by }) => performed_by)).toEqual([
      "admin",
      "admin",
      "outsider",
      "unavailable",
    ]);
    expect(rows.every(({ details }) => details.provider === "audit-fixture")).toBe(true);
    expect(JSON.stringify(rows)).not.toMatch(/correct|wrong-password|"password"/);
  });
});
