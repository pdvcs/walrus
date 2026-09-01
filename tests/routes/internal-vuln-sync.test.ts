import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { createInternalRouter } from "../../src/routes/internal.js";
import { VulnSyncAlreadyRunningError } from "../../src/vuln/sync/lock.js";
import type { VulnSyncImpls } from "../../src/vuln/sync/index.js";

function appWith(
  vulnSync: VulnSyncImpls,
  vulnHints?: () => Promise<string[]>,
  logAdminAction?: (details: Record<string, unknown>) => Promise<void>,
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
      logAdminAction,
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
    // 502, not 207: one named source has one outcome, and reporting its total failure as a
    // partial success let Cloud Scheduler record the attempt as fine and skip the retry (WAL-108).
    expect(res.status).toBe(502);
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

describe("retired internal backfill endpoints", () => {
  it("leaves operator-initiated backfill to /admin/v1", async () => {
    const app = appWith({});
    await request(app).post("/internal/vuln-backfill").expect(404);
    await request(app).get("/internal/vuln-backfill/42").expect(404);
  });
});

describe("POST /internal/vuln-sync/cvss dry runs", () => {
  const proposal = {
    cve_id: "CVE-2026-1111",
    severity: "CRITICAL",
    severity_source: "nvd-cvss-v3",
    cvss_v3_score: 9.8,
    cvss_v4_score: null,
    cvss_v2_score: null,
    crosses_critical_gate: true,
  };

  it("previews without applying, reporting the versions that would become blocked", async () => {
    let applied = false;
    const app = appWith({
      cvss: async () => {
        applied = true;
        return { updated: 7 };
      },
      cvssPreview: async () => ({
        candidates: 3,
        fetched: 3,
        proposals: [proposal],
        newly_blocked: [{ package_name: "golang", newly_blocked: ["1.26.4"] }],
      }),
    });

    const res = await request(app).post("/internal/vuln-sync/cvss").send({ dry_run: true });

    expect(res.status).toBe(200);
    expect(res.body.dry_run).toBe(true);
    expect(res.body.preview.proposals).toEqual([proposal]);
    expect(res.body.preview.newly_blocked).toEqual([
      { package_name: "golang", newly_blocked: ["1.26.4"] },
    ]);
    // The whole point: a preview must never reach the writing path.
    expect(applied).toBe(false);
  });

  it("rejects dry_run for a source that cannot honour it, without running it", async () => {
    let ran = false;
    const app = appWith({
      nvd: async () => {
        ran = true;
        return { cves: 1 };
      },
    });

    const res = await request(app).post("/internal/vuln-sync/nvd").send({ dry_run: true });

    expect(res.status).toBe(400);
    expect(res.body.error).toContain("only supported for the 'cvss' source");
    // Silently ignoring the flag would run a live sync for someone who asked to preview.
    expect(ran).toBe(false);
  });

  it("rejects limit for a source that cannot honour it", async () => {
    const app = appWith({ nvd: async () => ({ cves: 1 }) });
    const res = await request(app).post("/internal/vuln-sync/nvd").send({ limit: 10 });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("only supported for the 'cvss' source");
  });

  it("passes limit through to the cvss apply", async () => {
    let seen: number | undefined;
    const app = appWith({
      cvss: async (opts) => {
        seen = opts?.limit;
        return { updated: 2 };
      },
    });

    const res = await request(app).post("/internal/vuln-sync/cvss").send({ limit: 25 });

    expect(res.status).toBe(200);
    expect(seen).toBe(25);
  });

  it("rejects a non-positive or non-integer limit", async () => {
    const app = appWith({ cvss: async () => ({ updated: 0 }) });
    for (const limit of [0, -1, 2.5, "abc"]) {
      const res = await request(app).post("/internal/vuln-sync/cvss").send({ limit });
      expect(res.status).toBe(400);
      expect(res.body.error).toContain("positive integer");
    }
  });

  it("returns 503 when no preview implementation is wired", async () => {
    const app = appWith({ cvss: async () => ({ updated: 1 }) });
    const res = await request(app).post("/internal/vuln-sync/cvss").send({ dry_run: true });
    expect(res.status).toBe(503);
  });

  it("returns 409 when the shared nvd lock is held during a preview", async () => {
    const app = appWith({
      cvssPreview: async () => {
        throw new VulnSyncAlreadyRunningError("nvd");
      },
    });
    const res = await request(app).post("/internal/vuln-sync/cvss").send({ dry_run: true });
    expect(res.status).toBe(409);
    expect(res.body.code).toBe("already_running");
  });
});

describe("POST /internal/vuln-sync/:source auditing", () => {
  it("records the outcome of a machine-triggered sync", async () => {
    const audited: Record<string, unknown>[] = [];
    const app = appWith(
      { kev: async () => ({ flagged: 2 }) },
      undefined,
      async (d) => void audited.push(d),
    );

    const res = await request(app).post("/internal/vuln-sync/kev");

    expect(res.status).toBe(200);
    expect(audited).toHaveLength(1);
    expect(audited[0].action).toBe("vuln-sync");
    expect(audited[0].source).toBe("kev");
    expect((audited[0].outcomes as { summary: Record<string, number> }[])[0].summary).toEqual({
      flagged: 2,
    });
  });

  it("records a failed sync too, so a silent gap is not mistaken for no run", async () => {
    const audited: Record<string, unknown>[] = [];
    const app = appWith(
      {
        nvd: async () => {
          throw new Error("nvd upstream down");
        },
      },
      undefined,
      async (d) => void audited.push(d),
    );

    const res = await request(app).post("/internal/vuln-sync/nvd");

    expect(res.status).toBe(502);
    expect(audited).toHaveLength(1);
    expect((audited[0].outcomes as { ok: boolean }[])[0].ok).toBe(false);
  });

  it("records a cvss preview with the count of versions it would block", async () => {
    const audited: Record<string, unknown>[] = [];
    const app = appWith(
      {
        cvssPreview: async () => ({
          candidates: 2,
          fetched: 2,
          proposals: [
            {
              cve_id: "CVE-2026-3333",
              severity: "CRITICAL",
              severity_source: "nvd-cvss-v3",
              cvss_v3_score: 9.1,
              cvss_v4_score: null,
              cvss_v2_score: null,
              crosses_critical_gate: true,
            },
          ],
          newly_blocked: [{ package_name: "golang", newly_blocked: ["1.26.4", "1.26.5"] }],
        }),
      },
      undefined,
      async (d) => void audited.push(d),
    );

    const res = await request(app).post("/internal/vuln-sync/cvss").send({ dry_run: true });

    expect(res.status).toBe(200);
    expect(audited[0].action).toBe("vuln-sync-preview");
    expect(audited[0].newly_blocked).toBe(2);
  });

  it("does not audit a run rejected before it started", async () => {
    const audited: Record<string, unknown>[] = [];
    const app = appWith(
      { nvd: async () => ({ cves: 1 }) },
      undefined,
      async (d) => void audited.push(d),
    );

    const res = await request(app).post("/internal/vuln-sync/nvd").send({ dry_run: true });

    expect(res.status).toBe(400);
    expect(audited).toHaveLength(0);
  });

  /**
   * WAL-108. The status code is what Cloud Scheduler reads to decide whether a tick worked and
   * whether to retry it, so the matrix is load-bearing rather than cosmetic. `207` on a single
   * failed source meant the scheduler recorded success, never retried, and WAL-106's retry — added
   * for precisely this sort of lost run — could not fire.
   *
   * Mutation check: restore `allOk ? 200 : alreadyRunning ? 409 : 207` in `internal.ts` and the
   * single-source failure cases below fail while the `all` cases still pass.
   */
  describe("status matrix (WAL-108)", () => {
    it("answers 502 when the only source of a named sync failed", async () => {
      const app = appWith({
        nvd: async () => {
          throw new Error("nvd upstream down");
        },
      });
      const res = await request(app).post("/internal/vuln-sync/nvd");
      expect(res.status).toBe(502);
      expect(res.body.outcomes[0].ok).toBe(false);
    });

    it("still answers 207 for all, where the set genuinely can be partial", async () => {
      // The distinction the fix turns on: here one status code cannot describe three outcomes,
      // so 207 is the honest answer and a retry of the whole set is not obviously right.
      const app = appWith({
        nvd: async () => ({ affects: 1 }),
        kev: async () => {
          throw new Error("kev upstream down");
        },
        osv: async () => ({ affectsUpserted: 1 }),
      });
      const res = await request(app).post("/internal/vuln-sync/all");
      expect(res.status).toBe(207);
    });

    it("answers 200 for a named source that succeeded", async () => {
      const app = appWith({ nvd: async () => ({ affects: 1 }) });
      expect((await request(app).post("/internal/vuln-sync/nvd")).status).toBe(200);
    });

    it("keeps 409 for contention, which must not consume a retry", async () => {
      // Contention is not a failure: something else is already doing the work. Answering 5xx here
      // would spend the retry budget on a run that was never needed — the same rule
      // `autoBackfillPendingPackages` follows when it refunds an attempt after `already_running`.
      const app = appWith({
        nvd: async () => {
          throw new VulnSyncAlreadyRunningError("nvd");
        },
      });
      const res = await request(app).post("/internal/vuln-sync/nvd");
      expect(res.status).toBe(409);
      expect(res.body.outcomes[0].code).toBe("already_running");
    });
  });
});
