import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { createInternalRouter } from "../../src/routes/internal.js";
import { VulnSyncAlreadyRunningError } from "../../src/vuln/sync/lock.js";
import type { VulnBackfillJobRow } from "../../src/db/queries/vuln-backfill-jobs.js";

function appWith(
  vulnSync: Record<string, () => Promise<Record<string, number>>>,
  vulnHints?: () => Promise<string[]>,
  backfill?: {
    start: (since?: string) => Promise<{ job: VulnBackfillJobRow; alreadyRunning?: boolean }>;
    get: (id: string) => Promise<VulnBackfillJobRow | null>;
  },
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
      startVulnBackfill: backfill?.start,
      getVulnBackfill: backfill?.get,
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

  it("returns 409 with an already_running outcome for a direct overlap", async () => {
    const app = appWith({
      nvd: async () => {
        throw new VulnSyncAlreadyRunningError("nvd");
      },
    });
    const res = await request(app).post("/internal/vuln-sync/nvd");
    expect(res.status).toBe(409);
    expect(res.body.outcomes[0]).toMatchObject({ ok: false, code: "already_running" });
  });

  it("continues an all sync when one source is already running", async () => {
    const app = appWith({
      nvd: async () => {
        throw new VulnSyncAlreadyRunningError("nvd");
      },
      kev: async () => ({ flagged: 1 }),
      osv: async () => ({ affectsUpserted: 1 }),
    });
    const res = await request(app).post("/internal/vuln-sync/all");
    expect(res.status).toBe(207);
    expect(res.body.outcomes[0].code).toBe("already_running");
    expect(res.body.outcomes.slice(1).every((outcome: { ok: boolean }) => outcome.ok)).toBe(true);
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

const backfillJob = (status: VulnBackfillJobRow["status"] = "queued"): VulnBackfillJobRow => ({
  id: "42",
  status,
  since_date: "2020-01-01",
  cpe_pairs_total: 3,
  cpe_pairs_done: 1,
  error_message: null,
  execution_name: "operations/abc",
  started_at: null,
  finished_at: null,
  created_at: new Date("2026-07-11T12:00:00Z"),
});

describe("NVD backfill HTTP jobs", () => {
  it("returns 202 with a durable job reference", async () => {
    const start = async () => ({ job: backfillJob() });
    const app = appWith({}, undefined, { start, get: async () => null });
    const res = await request(app).post("/internal/vuln-backfill").send({ since: "2020-01-01" });
    expect(res.status).toBe(202);
    expect(res.body).toMatchObject({
      job: { id: "42", status: "queued" },
      status_url: "/internal/vuln-backfill/42",
    });
  });

  it("returns 409 when a backfill is active", async () => {
    const start = async () => ({ job: backfillJob("running"), alreadyRunning: true });
    const res = await request(appWith({}, undefined, { start, get: async () => null }))
      .post("/internal/vuln-backfill")
      .send({});
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("already_running");
  });

  it("rejects invalid since dates", async () => {
    const start = async () => ({ job: backfillJob() });
    const res = await request(appWith({}, undefined, { start, get: async () => null }))
      .post("/internal/vuln-backfill")
      .send({ since: "2026-02-30" });
    expect(res.status).toBe(400);
  });

  it("returns job lifecycle status", async () => {
    const get = async () => backfillJob("succeeded");
    const res = await request(
      appWith({}, undefined, { start: async () => ({ job: backfillJob() }), get }),
    ).get("/internal/vuln-backfill/42");
    expect(res.status).toBe(200);
    expect(res.body.job).toMatchObject({
      id: "42",
      status: "succeeded",
      cpe_pairs_done: 1,
      cpe_pairs_total: 3,
    });
  });
});
