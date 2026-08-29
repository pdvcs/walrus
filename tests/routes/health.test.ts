import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { pool, runMigrations } from "../../src/db/client.js";
import { createApp } from "../../src/main.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { upsertCveFull } from "../../src/db/queries/cves.js";
import { createCveSuppression } from "../../src/db/queries/cve-suppressions.js";

const HEALTH_PACKAGE = "health-suppression-package";
const HEALTH_CVE = "CVE-2099-7070";

describe("GET /health", () => {
  beforeAll(async () => {
    await runMigrations();
  });

  it("includes vuln_data_freshness with per-source nullable timestamps and passes its schema", async () => {
    const app = createApp();
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.service).toBe("walrus");
    expect(res.body).toHaveProperty("vuln_data_freshness");
    // Each source key exists (value may be null before a first sync).
    const f = res.body.vuln_data_freshness;
    expect(f).toHaveProperty("nvd_last_sync");
    expect(f).toHaveProperty("kev_last_sync");
    expect(f).toHaveProperty("osv_last_sync");
    expect(f).toHaveProperty("cvss_last_sync");
    expect(res.body).toHaveProperty("vuln_sync_status");
    expect(res.body.vuln_sync_status).toHaveProperty("nvd.last_ok");
    expect(res.body.vuln_sync_status).toHaveProperty("kev.last_failure");
    expect(res.body.vuln_sync_status).toHaveProperty("osv.last_attempt");
    expect(res.body.vuln_sync_status).toHaveProperty("cvss.last_attempt");
  });

  it("reports degradations without leaving status ok (status is for major events)", async () => {
    const app = createApp();
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    // Degradations are additive information; status stays "ok" regardless of them.
    expect(res.body.status).toBe("ok");
    expect(Array.isArray(res.body.degradations)).toBe(true);
    for (const d of res.body.degradations) {
      expect(d).toHaveProperty("component");
      expect(d).toHaveProperty("reason");
    }
  });

  it("reports active suppression counts and removes the degradation after expiry", async () => {
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
      const active = await request(createApp()).get("/health");
      expect(active.status).toBe(200);
      expect(active.body.status).toBe("ok");
      expect(active.body.degradations).toContainEqual({
        component: "cve-suppressions",
        reason:
          "1 operator CVE suppression active; review the list regularly for a missing general rule or an assertion that can be retired.",
      });

      await pool.query(
        "UPDATE cve_suppressions SET expires_at = now() - interval '1 second' WHERE id = $1",
        [suppression.id],
      );
      const expired = await request(createApp()).get("/health");
      expect(
        expired.body.degradations.some(
          (item: { component: string }) => item.component === "cve-suppressions",
        ),
      ).toBe(false);
    } finally {
      await pool.query("DELETE FROM cves WHERE id = $1", [HEALTH_CVE]);
      await pool.query("DELETE FROM packages WHERE name = $1", [HEALTH_PACKAGE]);
    }
  });
});
