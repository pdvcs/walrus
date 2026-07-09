import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { createInternalRouter } from "../../src/routes/internal.js";

function appWith(
  vulnSync: Record<string, () => Promise<Record<string, number>>>,
  vulnHints?: () => Promise<string[]>,
) {
  const app = express();
  app.use(express.json());
  app.use(
    "/internal",
    createInternalRouter({
      runSync: async () => {
        throw new Error("unused");
      },
      runSyncAll: async () => [],
      vulnSync,
      vulnHints,
    }),
  );
  return app;
}

describe("POST /internal/vuln-sync/:source", () => {
  it("runs the nvd source and returns a per-source summary (200)", async () => {
    const app = appWith({
      nvd: async () => ({ cves: 21, affects: 30, skippedCpes: 5 }),
    });
    const res = await request(app).post("/internal/vuln-sync/nvd");
    expect(res.status).toBe(200);
    expect(res.body.source).toBe("nvd");
    expect(res.body.outcomes).toHaveLength(1);
    expect(res.body.outcomes[0]).toMatchObject({ source: "nvd", ok: true });
    expect(res.body.outcomes[0].summary.affects).toBe(30);
  });

  it("rejects an unknown source with 400", async () => {
    const app = appWith({ nvd: async () => ({}) });
    const res = await request(app).post("/internal/vuln-sync/bogus");
    expect(res.status).toBe(400);
  });

  it("all: continues past a failing source and reports each (207)", async () => {
    const app = appWith({
      nvd: async () => ({ affects: 3 }),
      kev: async () => {
        throw new Error("kev upstream down");
      },
      osv: async () => ({ affectsUpserted: 1 }),
    });
    const res = await request(app).post("/internal/vuln-sync/all");
    expect(res.status).toBe(207);
    const bySource = Object.fromEntries(
      res.body.outcomes.map((o: { source: string }) => [o.source, o]),
    );
    expect(bySource.nvd.ok).toBe(true);
    expect(bySource.kev.ok).toBe(false);
    expect(bySource.kev.error).toMatch(/kev upstream down/);
    expect(bySource.osv.ok).toBe(true);
  });

  it("reports a not-available source as not-ok without throwing", async () => {
    const app = appWith({ nvd: async () => ({}) }); // no kev/osv provided
    const res = await request(app).post("/internal/vuln-sync/kev");
    expect(res.status).toBe(207);
    expect(res.body.outcomes[0].ok).toBe(false);
  });

  it("appends operator hints to the sync response when present", async () => {
    const app = appWith({ nvd: async () => ({ affects: 0 }) }, async () => ["run vuln:backfill"]);
    const res = await request(app).post("/internal/vuln-sync/nvd");
    expect(res.body.hints).toEqual(["run vuln:backfill"]);
  });

  it("omits the hints field when there are none", async () => {
    const app = appWith({ nvd: async () => ({ affects: 5 }) }, async () => []);
    const res = await request(app).post("/internal/vuln-sync/nvd");
    expect(res.body).not.toHaveProperty("hints");
  });
});
