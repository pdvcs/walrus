import { beforeAll, describe, expect, it, vi } from "vitest";
import request from "supertest";
import { pool, runMigrations } from "../../src/db/client.js";
import { createApp } from "../../src/main.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { upsertCveFull } from "../../src/db/queries/cves.js";
import { createCveSuppression } from "../../src/db/queries/cve-suppressions.js";
import { configureEgress } from "../../src/common/egress-rules.js";

const HEALTH_PACKAGE = "health-suppression-package";
const HEALTH_CVE = "CVE-2099-7070";
const STARTED = new Date("2026-08-29T15:10:00.000Z");
const DURING_GRACE = new Date("2026-08-29T15:14:03.662Z");
const AFTER_GRACE = new Date("2026-08-29T15:15:01.000Z");

describe("application health and status", () => {
  beforeAll(async () => {
    await runMigrations();
  });

  it("serves minimal package and startup metadata from both health aliases", async () => {
    const checkDatabase = vi.fn().mockResolvedValue(undefined);
    const app = createApp({
      health: { startedAt: STARTED, now: () => DURING_GRACE, checkDatabase },
    });
    const [health, alias] = await Promise.all([
      request(app).get("/health"),
      request(app).get("/app/health"),
    ]);

    expect(health.status).toBe(200);
    expect(alias.status).toBe(200);
    expect(health.body).toEqual(alias.body);
    expect(health.body).toEqual({
      isAvailable: true,
      gitUrl: "https://github.com/pdvcs/walrus",
      ts: "2026-08-29T15:14:03.662Z",
      started: "2026-08-29T15:10:00.000Z",
      inGracePeriod: true,
      version: "0.2.0",
    });
    expect(health.body).not.toHaveProperty("status");
    expect(health.body).not.toHaveProperty("service");
    expect(checkDatabase).toHaveBeenCalledOnce();
  });

  it("caches a successful database probe for 60 seconds across health aliases", async () => {
    let current = AFTER_GRACE;
    const checkDatabase = vi.fn().mockResolvedValue(undefined);
    const app = createApp({
      health: { startedAt: STARTED, now: () => current, checkDatabase },
    });

    expect((await request(app).get("/health")).body.isAvailable).toBe(true);
    current = new Date(AFTER_GRACE.getTime() + 59_999);
    expect((await request(app).get("/app/health")).body.isAvailable).toBe(true);
    expect(checkDatabase).toHaveBeenCalledOnce();

    current = new Date(AFTER_GRACE.getTime() + 60_000);
    expect((await request(app).get("/health")).body.isAvailable).toBe(true);
    expect(checkDatabase).toHaveBeenCalledTimes(2);
  });

  it("caches a failed database probe and retries after 60 seconds", async () => {
    let current = AFTER_GRACE;
    const checkDatabase = vi
      .fn()
      .mockRejectedValueOnce(new Error("database unavailable"))
      .mockResolvedValue(undefined);
    const app = createApp({
      health: { startedAt: STARTED, now: () => current, checkDatabase },
    });

    expect((await request(app).get("/health")).status).toBe(503);
    current = new Date(AFTER_GRACE.getTime() + 30_000);
    expect((await request(app).get("/app/health")).status).toBe(503);
    expect(checkDatabase).toHaveBeenCalledOnce();

    current = new Date(AFTER_GRACE.getTime() + 60_000);
    expect((await request(app).get("/health")).status).toBe(200);
    expect(checkDatabase).toHaveBeenCalledTimes(2);
  });

  it("coalesces concurrent health requests into one database probe", async () => {
    let resolveProbe: (() => void) | undefined;
    const checkDatabase = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          resolveProbe = resolve;
        }),
    );
    const app = createApp({
      health: { startedAt: STARTED, now: () => AFTER_GRACE, checkDatabase },
    });

    const responsesPromise = Promise.all([
      request(app).get("/health"),
      request(app).get("/app/health"),
    ]);
    await vi.waitFor(() => expect(checkDatabase).toHaveBeenCalledOnce());
    resolveProbe?.();
    const responses = await responsesPromise;

    expect(responses.map((response) => response.status)).toEqual([200, 200]);
    expect(checkDatabase).toHaveBeenCalledOnce();
  });

  it("stays available during startup grace when the database is unavailable", async () => {
    const app = createApp({
      health: {
        startedAt: STARTED,
        now: () => DURING_GRACE,
        checkDatabase: () => Promise.reject(new Error("database unavailable")),
      },
    });

    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.isAvailable).toBe(true);
    expect(res.body.inGracePeriod).toBe(true);
  });

  it("returns 503 after grace when the database is unavailable", async () => {
    const app = createApp({
      health: {
        startedAt: STARTED,
        now: () => AFTER_GRACE,
        checkDatabase: () => Promise.reject(new Error("database unavailable")),
      },
    });

    const res = await request(app).get("/health");
    expect(res.status).toBe(503);
    expect(res.body.isAvailable).toBe(false);
    expect(res.body.inGracePeriod).toBe(false);
  });

  it("is available after grace when the database probe succeeds", async () => {
    const app = createApp({
      health: { startedAt: STARTED, now: () => AFTER_GRACE, checkDatabase: async () => {} },
    });

    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.isAvailable).toBe(true);
    expect(res.body.inGracePeriod).toBe(false);
  });

  it("publishes both health paths and detailed status in OpenAPI", async () => {
    const spec = (await request(createApp()).get("/openapi.json")).body;

    expect(spec.paths["/health"].get.responses).toHaveProperty("503");
    expect(spec.paths["/app/health"].get.responses).toHaveProperty("503");
    expect(spec.paths["/app/status"].get.responses).toHaveProperty("503");
    expect(spec.components.schemas.HealthResponse.required).toEqual([
      "isAvailable",
      "gitUrl",
      "ts",
      "started",
      "inGracePeriod",
      "version",
    ]);
    expect(spec.components.schemas.StatusResponse.allOf[1].required).toContain("degradations");
  });

  it("moves vulnerability freshness, sync status, and degradations to /app/status", async () => {
    const app = createApp({
      health: { startedAt: STARTED, now: () => AFTER_GRACE, checkDatabase: async () => {} },
    });
    const res = await request(app).get("/app/status");

    expect(res.status).toBe(200);
    expect(res.body.isAvailable).toBe(true);
    expect(res.body.inGracePeriod).toBe(false);
    expect(res.body).toHaveProperty("vuln_data_freshness");
    const freshness = res.body.vuln_data_freshness;
    expect(freshness).toHaveProperty("nvd_last_sync");
    expect(freshness).toHaveProperty("kev_last_sync");
    expect(freshness).toHaveProperty("osv_last_sync");
    expect(freshness).toHaveProperty("cvss_last_sync");
    expect(res.body).toHaveProperty("vuln_sync_status");
    expect(res.body.vuln_sync_status).toHaveProperty("nvd.last_ok");
    expect(res.body.vuln_sync_status).toHaveProperty("kev.last_failure");
    expect(res.body.vuln_sync_status).toHaveProperty("osv.last_attempt");
    expect(res.body.vuln_sync_status).toHaveProperty("cvss.last_attempt");
    expect(Array.isArray(res.body.degradations)).toBe(true);
    expect(res.body).not.toHaveProperty("status");
    expect(res.body).not.toHaveProperty("service");
  });

  it("reports the effective egress mode and rule count on /app/status", async () => {
    configureEgress({
      mode: "strict",
      rules: [{ match: "https://", rewrite: "http://localhost:9000/proxy/https://" }],
    });
    try {
      const app = createApp({
        health: { startedAt: STARTED, now: () => AFTER_GRACE, checkDatabase: async () => {} },
      });
      const res = await request(app).get("/app/status");

      expect(res.status).toBe(200);
      expect(res.body.egress).toEqual({ mode: "strict", rule_count: 1 });
    } finally {
      configureEgress({ mode: "direct", rules: [] });
    }
  });

  it("reports degradations without changing availability", async () => {
    const app = createApp({
      health: { startedAt: STARTED, now: () => AFTER_GRACE, checkDatabase: async () => {} },
    });
    const res = await request(app).get("/app/status");

    expect(res.status).toBe(200);
    expect(res.body.isAvailable).toBe(true);
    expect(Array.isArray(res.body.degradations)).toBe(true);
    for (const degradation of res.body.degradations) {
      expect(degradation).toHaveProperty("component");
      expect(degradation).toHaveProperty("reason");
    }
  });

  it("reports active suppressions as their own status object, never as a degradation", async () => {
    await upsertPackage(pool, {
      name: HEALTH_PACKAGE,
      display_name: HEALTH_PACKAGE,
      vendor: "Test",
      description: null,
      website: null,
      config_hash: "health-test",
      enabled: true,
    });
    await upsertCveFull(pool, {
      id: HEALTH_CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: 9.8,
      cvss_v3_vector: null,
      severity: "CRITICAL",
      description: "Health suppression fixture",
      raw: { cve: { id: HEALTH_CVE } },
    });

    try {
      const suppression = await createCveSuppression(pool, {
        cve_id: HEALTH_CVE,
        package_name: HEALTH_PACKAGE,
        reason: "Temporary health fixture",
        created_by: "operator@example.com",
        expires_at: new Date(Date.now() + 60_000),
      });
      const active = await request(createApp()).get("/app/status");
      expect(active.status).toBe(200);
      expect(active.body.isAvailable).toBe(true);
      expect(active.body.cve_suppressions.active_count).toBe(1);
      expect(active.body.cve_suppressions.next_expiry).toBe(suppression.expires_at?.toISOString());
      // A suppression is an audited decision, not machinery failing.
      expect(
        active.body.degradations.some(
          (item: { component: string }) => item.component === "cve-suppressions",
        ),
      ).toBe(false);

      await pool.query(
        "UPDATE cve_suppressions SET expires_at = now() - interval '1 second' WHERE id = $1",
        [suppression.id],
      );
      const expired = await request(createApp()).get("/app/status");
      expect(expired.body.cve_suppressions).toEqual({ active_count: 0, next_expiry: null });
    } finally {
      await pool.query("DELETE FROM cves WHERE id = $1", [HEALTH_CVE]);
      await pool.query("DELETE FROM packages WHERE name = $1", [HEALTH_PACKAGE]);
    }
  });
});
