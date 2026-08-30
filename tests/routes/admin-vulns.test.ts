import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { runInNewContext } from "node:vm";
import express from "express";
import request from "supertest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion } from "../../src/db/queries/versions.js";
import { reconcilePackageVuln } from "../../src/db/queries/package-aliases.js";
import { upsertCveFull, insertAffects } from "../../src/db/queries/cves.js";
import { insertAdminAction } from "../../src/db/queries/admin-actions.js";
import { generateSortKey } from "../../src/common/version-utils.js";
import { createAdminVulnsRouter } from "../../src/routes/admin-vulns.js";
import { createApp } from "../../src/main.js";
import type { VulnQueryResult } from "../../src/services/vuln-query.js";
import { VulnSyncAlreadyRunningError } from "../../src/vuln/sync/lock.js";
import { testOperatorAuth } from "../helpers/authn.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

function resolvedResult(): VulnQueryResult {
  return {
    query: { product: "openjdk", version: "11.0.2" },
    match: {
      resolved: true,
      product_slug: "openjdk",
      display_name: "OpenJDK",
      confidence: 1.0,
      method: "slug-exact",
      candidates: [],
    },
    vulns: [
      {
        cve_id: "CVE-2023-0001",
        severity: "CRITICAL",
        severity_source: "nvd-cvss-v3",
        cvss_v3_score: 9.8,
        cvss_v4_score: null,
        cvss_v2_score: null,
        summary: "boom",
        affected: { range: "< 20", matched_because: "11.0.2 < 20" },
        fixed_in: "20",
        is_kev: true,
        sources: ["nvd"],
        references: [],
        suppression: null,
      },
    ],
    counts: { total: 1, critical: 1, high: 0, medium: 0, low: 0, kev: 1 },
    data_freshness: { nvd_last_sync: null, kev_last_sync: null, osv_last_sync: null },
    disclaimer: "d",
  };
}

function unresolvedResult(): VulnQueryResult {
  return {
    query: { product: "asdfgh", version: null },
    match: {
      resolved: false,
      product_slug: null,
      display_name: null,
      confidence: null,
      method: null,
      candidates: [{ slug: "openjdk", display_name: "OpenJDK", score: 40 }],
    },
    vulns: [],
    counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, kev: 0 },
    data_freshness: { nvd_last_sync: null, kev_last_sync: null, osv_last_sync: null },
    disclaimer: "d",
  };
}

describe("admin vuln explorer + sync (isolated)", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });
  afterAll(async () => {
    await pool.query(`DELETE FROM admin_actions WHERE action_type = 'vuln-sync'`);
    await pool.end();
  });

  function buildApp(overrides: Partial<Parameters<typeof createAdminVulnsRouter>[0]> = {}) {
    const app = express();
    // Mirrors main.ts: the real app parses JSON *and* urlencoded bodies before the admin
    // router sees them. The urlencoded parser is not optional here — the admin UI posts plain
    // HTML forms, and without it every field is dropped silently (WAL-71).
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    app.use(
      "/admin/v1",
      createAdminVulnsRouter({
        startVulnBackfill: async () => ({
          job: {
            id: 42,
            status: "queued" as const,
            since_date: null,
            cpe_pairs_total: 0,
            cpe_pairs_done: 0,
            error_message: null,
            execution_name: "test:42",
            started_at: null,
            finished_at: null,
            created_at: new Date(),
            package_name: null,
          },
        }),
        getVulnBackfill: async () => null,
        queryVulns: async (product) =>
          product === "asdfgh" ? unresolvedResult() : resolvedResult(),
        getDataFreshness: async () => ({
          nvd_last_sync: null,
          kev_last_sync: null,
          osv_last_sync: null,
          cvss_last_sync: null,
        }),
        getSyncStatus: async () => ({
          nvd: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
          kev: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
          osv: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
          cvss: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
        }),
        getActiveSuppressionCount: async () => 0,
        listActiveSuppressions: async () => [],
        listSuppressionAudit: async () => [],
        cveExists: async () => true,
        packageExists: async () => true,
        previewSuppression: async (input) => ({
          action: "suppress",
          cve_id: input.cve_id,
          package_name: input.package_name,
          newly_available: [],
          newly_blocked: [],
          versions_changed: 0,
        }),
        createSuppression: async (input) => ({
          id: 1,
          ...input,
          created_at: new Date(),
          revoked_at: null,
        }),
        previewSuppressionRevocation: async (_id) => ({
          action: "revoke",
          cve_id: "CVE-2023-0001",
          package_name: "openjdk",
          newly_available: [],
          newly_blocked: [],
          versions_changed: 0,
        }),
        revokeSuppression: async ({ id }) => ({
          id,
          cve_id: "CVE-2023-0001",
          package_name: "openjdk",
          reason: "not applicable",
          created_by: "operator@example.com",
          created_at: new Date(),
          expires_at: null,
          revoked_at: new Date(),
        }),
        vulnSyncImpls: { kev: async () => ({ flagged: 3, cleared: 0, skippedUnknown: 0 }) },
        logAdminAction: (details) => insertAdminAction(pool, { action_type: "vuln-sync", details }),
        ...overrides,
      }),
    );
    return app;
  }

  it("renders the explorer page (200 text/html) with status strip + sync buttons", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns");
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/html/);
    expect(res.text).toMatch(/Vulnerability Explorer/);
    expect(res.text).toMatch(/Data sources/);
    expect(res.text).toMatch(/Sync KEV/);
    // Chips carry data-ts for the client-side relative-time rendering, and the
    // never-attempted state is a chip class, not prose.
    expect(res.text).toMatch(/class="src-chip src-never"/);
    expect(res.text).toMatch(/data-ts=""/);
    // Lookup form precedes the status strip: the primary task sits first.
    const formAt = res.text.indexOf('id="product"');
    const stripAt = res.text.indexOf("status-strip");
    expect(formAt).toBeGreaterThan(-1);
    expect(stripAt).toBeGreaterThan(formAt);
  });

  it("renders failed and succeeded source states as differently-colored chips", async () => {
    const failure = "2026-07-10T10:00:00.000Z";
    const res = await request(
      buildApp({
        getSyncStatus: async () => ({
          nvd: {
            last_attempt: failure,
            last_success: "2026-07-09T10:00:00.000Z",
            last_failure: failure,
            last_ok: false,
          },
          kev: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
          osv: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
          cvss: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
        }),
      }),
    ).get("/admin/v1/vulns");
    expect(res.text).toMatch(/class="src-chip src-fail"/);
    expect(res.text).toMatch(/src-chip src-never/);
    // Failure detail (absolute timestamp) lives in the tooltip, not the strip text.
    expect(res.text).toMatch(/last attempt FAILED 2026-07-10 10:00 UTC/);
  });

  it("renders the CVSS enrichment panel with Apply locked until a preview runs", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns");
    expect(res.text).toMatch(/CVSS enrichment/);
    expect(res.text).toMatch(/id="cvss-preview"/);
    // Applying without previewing is the mistake the panel exists to prevent, so the
    // button ships disabled and the script only unlocks it after a successful preview.
    expect(res.text).toMatch(/id="cvss-apply"[^>]*disabled/);
  });

  it("previews cvss enrichment without applying, and audits the preview", async () => {
    let applied = false;
    const app = buildApp({
      vulnSyncImpls: {
        cvss: async () => {
          applied = true;
          return { updated: 4 };
        },
        cvssPreview: async () => ({
          candidates: 1,
          fetched: 1,
          proposals: [
            {
              cve_id: "CVE-2026-2222",
              severity: "CRITICAL",
              severity_source: "nvd-cvss-v3",
              cvss_v3_score: 9.9,
              cvss_v4_score: null,
              cvss_v2_score: null,
              crosses_critical_gate: true,
            },
          ],
          newly_blocked: [{ package_name: "golang", newly_blocked: ["1.26.4"] }],
        }),
      },
    });

    const res = await request(app)
      .post("/admin/v1/vuln-sync/cvss")
      .send({ dry_run: true, limit: 5 });

    expect(res.status).toBe(200);
    expect(res.body.dry_run).toBe(true);
    expect(res.body.preview.newly_blocked).toEqual([
      { package_name: "golang", newly_blocked: ["1.26.4"] },
    ]);
    expect(applied).toBe(false);

    const { rows } = await pool.query(
      "SELECT details FROM admin_actions WHERE details->>'action' = 'vuln-sync-preview' ORDER BY id DESC LIMIT 1",
    );
    expect(rows[0].details.newly_blocked).toBe(1);
  });

  it("rejects a dry run for a source that cannot honour it", async () => {
    const res = await request(buildApp()).post("/admin/v1/vuln-sync/kev").send({ dry_run: true });
    expect(res.status).toBe(400);
    expect(res.body.error).toContain("only supported for the 'cvss' source");
  });

  it("renders a CVE table for a resolved query", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns?product=openjdk&version=11.0.2");
    expect(res.text).toContain("CVE-2023-0001");
    expect(res.text).toMatch(/CRITICAL/);
    expect(res.text).toMatch(/KEV/);
    expect(res.text).toContain("Suppress");
    expect(res.text).toMatch(/id="suppression-apply"[^>]*disabled/);
    expect(res.text).toContain("six-eyes review and formal approval");
  });

  it("lists active suppressions under the anchor the nav chip links to", async () => {
    const res = await request(
      buildApp({
        getActiveSuppressionCount: async () => 1,
        listActiveSuppressions: async () => [
          {
            id: 42,
            cve_id: "CVE-2023-0001",
            package_name: "openjdk",
            reason: "Confirmed mis-attribution",
            created_by: "operator@example.com",
            created_at: new Date("2026-08-29T10:00:00Z"),
            expires_at: null,
            revoked_at: null,
          },
        ],
      }),
    ).get("/admin/v1/vulns");
    expect(res.text).toContain('id="active-suppressions"');
    expect(res.text).toContain("Active CVE suppressions (1)");
    expect(res.text).toContain("Confirmed mis-attribution");
    expect(res.text).toContain("operator@example.com");
    expect(res.text).toMatch(/data-mode="revoke" data-id="42"/);
  });

  it("serves the active suppression count the nav chip polls", async () => {
    const res = await request(buildApp({ getActiveSuppressionCount: async () => 3 })).get(
      "/admin/v1/vuln-suppressions/active-count",
    );
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ active_count: 3 });
  });

  it("keeps Apply locked in the browser until the exact suppression payload is previewed", async () => {
    class FakeElement {
      disabled = false;
      hidden = true;
      title = "";
      value = "";
      innerHTML = "";
      textContent = "";
      private listeners = new Map<string, Array<() => unknown>>();

      constructor(private attributes: Record<string, string> = {}) {}

      addEventListener(type: string, listener: () => unknown): void {
        const listeners = this.listeners.get(type) ?? [];
        listeners.push(listener);
        this.listeners.set(type, listeners);
      }

      getAttribute(name: string): string | null {
        return this.attributes[name] ?? null;
      }

      scrollIntoView(): void {}

      async dispatch(type: string): Promise<void> {
        for (const listener of this.listeners.get(type) ?? []) await listener();
      }
    }

    const response = await request(buildApp()).get(
      "/admin/v1/vulns?product=openjdk&version=11.0.2",
    );
    const startMarker = "// WAL-70 suppression-ui:start";
    const endMarker = "// WAL-70 suppression-ui:end";
    const start = response.text.indexOf(startMarker);
    const end = response.text.indexOf(endMarker);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const script = response.text.slice(start, end);

    const elements = new Map<string, FakeElement>();
    for (const id of [
      "suppression-panel",
      "suppression-title",
      "suppression-scope",
      "suppression-reason",
      "suppression-expiry",
      "suppression-expiry-wrap",
      "suppression-preview",
      "suppression-apply",
      "suppression-cancel",
      "suppression-out",
    ]) {
      elements.set(id, new FakeElement());
    }
    const open = new FakeElement({
      "data-mode": "suppress",
      "data-id": "",
      "data-cve": "CVE-2023-0001",
      "data-package": "openjdk",
      "data-scope": "openjdk",
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        json: async () => ({
          preview: {
            newly_available: [{ package_name: "openjdk", versions: ["11.0.2"] }],
            newly_blocked: [],
            versions_changed: 1,
          },
        }),
      })
      .mockResolvedValueOnce({
        status: 200,
        json: async () => ({
          preview: { newly_available: [], newly_blocked: [], versions_changed: 0 },
        }),
      })
      .mockResolvedValueOnce({ status: 201, json: async () => ({ suppression: { id: 1 } }) });
    const reload = vi.fn();

    runInNewContext(script, {
      document: {
        getElementById: (id: string) => elements.get(id),
        querySelectorAll: (selector: string) => (selector === ".suppression-open" ? [open] : []),
      },
      fetch: fetchMock,
      confirm: vi.fn(() => true),
      window: { location: { reload } },
      esc: (value: unknown) => String(value),
    });

    await open.dispatch("click");
    const apply = elements.get("suppression-apply")!;
    const reason = elements.get("suppression-reason")!;
    expect(elements.get("suppression-panel")?.hidden).toBe(false);
    expect(apply.disabled).toBe(true);

    reason.value = "Confirmed false positive";
    await elements.get("suppression-preview")!.dispatch("click");
    expect(fetchMock.mock.calls[0][0]).toBe("/admin/v1/vuln-suppressions/preview");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toMatchObject({
      cve_id: "CVE-2023-0001",
      package_name: "openjdk",
      reason: "Confirmed false positive",
    });
    expect(apply.disabled).toBe(false);

    reason.value = "Changed after preview";
    await reason.dispatch("input");
    expect(apply.disabled).toBe(true);
    expect(apply.title).toContain("Preview this exact change first");

    await elements.get("suppression-preview")!.dispatch("click");
    expect(apply.disabled).toBe(false);
    await apply.dispatch("click");
    expect(fetchMock.mock.calls[2][0]).toBe("/admin/v1/vuln-suppressions");
    expect(JSON.parse(fetchMock.mock.calls[2][1].body).reason).toBe("Changed after preview");
    expect(reload).toHaveBeenCalledOnce();
  });

  it("renders a health degradation in the admin browser banner", async () => {
    const response = await request(buildApp()).get("/admin/v1/vulns");
    const startMarker = "// health-degradation-ui:start";
    const endMarker = "// health-degradation-ui:end";
    const start = response.text.indexOf(startMarker);
    const end = response.text.indexOf(endMarker);
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);

    const banner = { className: "", innerHTML: "" };
    const fetchMock = vi.fn(async () => ({
      ok: true,
      json: async () => ({
        isAvailable: true,
        degradations: [
          {
            component: "vuln-sync-nvd",
            reason: "nvd ingestion last succeeded 30h ago (threshold 12h).",
          },
        ],
      }),
    }));
    const execution = runInNewContext(response.text.slice(start, end), {
      fetch: fetchMock,
      document: {
        getElementById: (id: string) => (id === "degraded-banner" ? banner : null),
        createElement: () => {
          let html = "";
          return {
            get innerHTML() {
              return html;
            },
            set textContent(value: unknown) {
              html = typeof value === "string" ? value : (JSON.stringify(value) ?? "");
            },
          };
        },
      },
    });
    await execution;

    expect(fetchMock).toHaveBeenCalledWith("/app/status");
    expect(banner.className).toBe("degraded-banner");
    expect(banner.innerHTML).toContain("System degraded");
    expect(banner.innerHTML).toContain("vuln-sync-nvd");
    expect(banner.innerHTML).toContain("nvd ingestion last succeeded 30h ago");
  });

  it("rejects blank audit fields before previewing or applying a suppression", async () => {
    const app = buildApp();
    const preview = await request(app).post("/admin/v1/vuln-suppressions/preview").send({
      cve_id: "CVE-2023-0001",
      package_name: "openjdk",
      reason: "   ",
      created_by: "operator@example.com",
    });
    expect(preview.status).toBe(400);
    expect(preview.body.error).toContain("reason");

    const apply = await request(app).post("/admin/v1/vuln-suppressions").send({
      cve_id: "CVE-2023-0001",
      package_name: "openjdk",
      reason: "Confirmed false positive",
      created_by: "",
    });
    expect(apply.status).toBe(400);
    expect(apply.body.error).toContain("created_by");
  });

  it("validates suppression expiry and passes a future timestamp as a Date", async () => {
    const app = buildApp();
    for (const expires_at of ["not-a-date", "2020-01-01T00:00:00.000Z"]) {
      const res = await request(app).post("/admin/v1/vuln-suppressions/preview").send({
        cve_id: "CVE-2023-0001",
        package_name: "openjdk",
        reason: "Confirmed false positive",
        created_by: "operator@example.com",
        expires_at,
      });
      expect(res.status).toBe(400);
      expect(res.body.error).toContain("expires_at");
    }

    let receivedExpiry: Date | null = null;
    const future = new Date(Date.now() + 86_400_000).toISOString();
    const accepted = await request(
      buildApp({
        createSuppression: async (input) => {
          receivedExpiry = input.expires_at;
          return {
            id: 2,
            ...input,
            created_at: new Date(),
            revoked_at: null,
          };
        },
      }),
    )
      .post("/admin/v1/vuln-suppressions")
      .send({
        cve_id: "cve-2023-0001",
        package_name: "openjdk",
        reason: "Confirmed false positive",
        created_by: "operator@example.com",
        expires_at: future,
      });
    expect(accepted.status).toBe(201);
    expect(receivedExpiry?.toISOString()).toBe(future);
    expect(accepted.body.suppression.cve_id).toBe("CVE-2023-0001");
  });

  it("rejects unknown suppression scopes and maps duplicate scopes to 409", async () => {
    const unknownCve = await request(buildApp({ cveExists: async () => false }))
      .post("/admin/v1/vuln-suppressions")
      .send({
        cve_id: "CVE-2023-9999",
        reason: "Confirmed false positive",
        created_by: "operator@example.com",
      });
    expect(unknownCve.status).toBe(404);
    expect(unknownCve.body.error).toContain("Unknown CVE");

    const unknownPackage = await request(buildApp({ packageExists: async () => false }))
      .post("/admin/v1/vuln-suppressions/preview")
      .send({
        cve_id: "CVE-2023-0001",
        package_name: "missing",
        reason: "Confirmed false positive",
        created_by: "operator@example.com",
      });
    expect(unknownPackage.status).toBe(404);
    expect(unknownPackage.body.error).toContain("Unknown package");

    const duplicate = Object.assign(new Error("duplicate"), { code: "23505" });
    const conflict = await request(
      buildApp({
        createSuppression: async () => {
          throw duplicate;
        },
      }),
    )
      .post("/admin/v1/vuln-suppressions")
      .send({
        cve_id: "CVE-2023-0001",
        package_name: "openjdk",
        reason: "Confirmed false positive",
        created_by: "operator@example.com",
      });
    expect(conflict.status).toBe(409);
    expect(conflict.body.error).toContain("already exists");
  });

  it("validates revocation ids and returns 404 for missing suppressions", async () => {
    const app = buildApp({
      previewSuppressionRevocation: async () => null,
      revokeSuppression: async () => null,
    });
    const invalid = await request(app)
      .post("/admin/v1/vuln-suppressions/not-an-id/revoke/preview")
      .send({ reason: "No longer needed", revoked_by: "operator@example.com" });
    expect(invalid.status).toBe(400);
    expect(invalid.body.error).toContain("Invalid suppression id");

    const missingPreview = await request(app)
      .post("/admin/v1/vuln-suppressions/999/revoke/preview")
      .send({ reason: "No longer needed", revoked_by: "operator@example.com" });
    expect(missingPreview.status).toBe(404);

    const missingApply = await request(app)
      .post("/admin/v1/vuln-suppressions/999/revoke")
      .send({ reason: "No longer needed", revoked_by: "operator@example.com" });
    expect(missingApply.status).toBe(404);
  });

  it("lists suppression audit entries with CVE filtering and cursor pagination", async () => {
    let received: unknown;
    const res = await request(
      buildApp({
        listSuppressionAudit: async (opts) => {
          received = opts;
          return [
            {
              id: 12,
              action_type: "cve-suppression-revoked",
              package_name: "openjdk",
              version: null,
              performed_by: "second.operator@example.com",
              details: {
                cve_id: "CVE-2023-0001",
                reason: "Upstream attribution corrected",
              },
              created_at: new Date("2026-08-29T12:00:00.000Z"),
            },
            {
              id: 11,
              action_type: "cve-suppression-created",
              package_name: "openjdk",
              version: null,
              performed_by: "operator@example.com",
              details: { cve_id: "CVE-2023-0001", reason: "Confirmed false positive" },
              created_at: new Date("2026-08-29T11:00:00.000Z"),
            },
          ];
        },
      }),
    ).get("/admin/v1/vuln-suppressions/audit?limit=2&before_id=20&cve_id=cve-2023-0001");

    expect(res.status).toBe(200);
    expect(received).toEqual({ limit: 2, beforeId: 20, cveId: "CVE-2023-0001" });
    expect(res.body.actions).toHaveLength(2);
    expect(res.body.actions[0]).toMatchObject({
      id: 12,
      action_type: "cve-suppression-revoked",
      performed_by: "second.operator@example.com",
      created_at: "2026-08-29T12:00:00.000Z",
    });
    expect(res.body.next_before_id).toBe(11);
  });

  it("rejects invalid suppression audit pagination parameters", async () => {
    const app = buildApp();
    for (const query of ["limit=0", "limit=101", "limit=nope", "before_id=0", "cve_id="]) {
      const res = await request(app).get(`/admin/v1/vuln-suppressions/audit?${query}`);
      expect(res.status).toBe(400);
    }
  });

  it("previews over the API without applying and returns exact availability changes", async () => {
    let created = false;
    const app = buildApp({
      previewSuppression: async (input) => ({
        action: "suppress",
        cve_id: input.cve_id,
        package_name: input.package_name,
        newly_available: [{ package_name: "openjdk", versions: ["11.0.2"] }],
        newly_blocked: [],
        versions_changed: 1,
      }),
      createSuppression: async (input) => {
        created = true;
        return {
          id: 9,
          ...input,
          created_at: new Date(),
          revoked_at: null,
        };
      },
    });
    const res = await request(app).post("/admin/v1/vuln-suppressions/preview").send({
      cve_id: "CVE-2023-0001",
      package_name: "openjdk",
      reason: "Confirmed false positive",
      created_by: "operator@example.com",
    });
    expect(res.status).toBe(200);
    expect(res.body.preview).toMatchObject({
      versions_changed: 1,
      newly_available: [{ package_name: "openjdk", versions: ["11.0.2"] }],
    });
    expect(created).toBe(false);
  });

  it("applies a suppression through the API and records availability transitions", async () => {
    const transitions: string[] = [];
    const res = await request(
      buildApp({
        recordAvailability: async (source) => {
          transitions.push(source);
          return {
            newlyBlocked: [],
            newlyAvailable: [{ package_name: "openjdk", version: "11.0.2" }],
          };
        },
      }),
    )
      .post("/admin/v1/vuln-suppressions")
      .send({
        cve_id: "CVE-2023-0001",
        package_name: "openjdk",
        reason: "Confirmed false positive",
        created_by: "operator@example.com",
      });
    expect(res.status).toBe(201);
    expect(res.body.suppression).toMatchObject({
      cve_id: "CVE-2023-0001",
      package_name: "openjdk",
    });
    expect(transitions).toEqual(["suppression"]);
  });

  it("requires a reason and operator to preview and apply revocation", async () => {
    const app = buildApp();
    const invalid = await request(app)
      .post("/admin/v1/vuln-suppressions/1/revoke")
      .send({ reason: "", revoked_by: "operator@example.com" });
    expect(invalid.status).toBe(400);

    const transitions: string[] = [];
    const applied = await request(
      buildApp({
        recordAvailability: async (source) => {
          transitions.push(source);
          return {
            newlyBlocked: [{ package_name: "openjdk", version: "11.0.2", cve_id: "CVE-2023-0001" }],
            newlyAvailable: [],
          };
        },
      }),
    )
      .post("/admin/v1/vuln-suppressions/1/revoke")
      .send({ reason: "Attribution corrected", revoked_by: "operator@example.com" });
    expect(applied.status).toBe(200);
    expect(applied.body.suppression.revoked_at).toBeTruthy();
    expect(transitions).toEqual(["suppression"]);
  });

  it("renders the not-matched state with suggestions for garbage", async () => {
    const res = await request(buildApp()).get("/admin/v1/vulns?product=asdfgh");
    expect(res.text).toMatch(/Not matched/);
    expect(res.text).toMatch(/openjdk/); // candidate suggestion
  });

  it("surfaces operator hints (e.g. run vuln:backfill) as a banner", async () => {
    const app = buildApp({
      getHints: async () => ["No NVD vulnerability data yet — run `npm run vuln:backfill`."],
    });
    const res = await request(app).get("/admin/v1/vulns");
    expect(res.text).toMatch(/No NVD vulnerability data yet/);
    expect(res.text).toContain("<code>npm run vuln:backfill</code>"); // backtick → code
  });

  it("sync trigger runs, records an admin_actions row, returns outcomes", async () => {
    const res = await request(buildApp()).post("/admin/v1/vuln-sync/kev");
    expect(res.status).toBe(200);
    expect(res.body.outcomes[0]).toMatchObject({ source: "kev", ok: true });
    const { rows } = await pool.query(
      `SELECT details FROM admin_actions WHERE action_type = 'vuln-sync' ORDER BY id DESC LIMIT 1`,
    );
    expect(rows[0].details.source).toBe("kev");
  });

  it("unknown sync source → 400", async () => {
    const res = await request(buildApp()).post("/admin/v1/vuln-sync/bogus");
    expect(res.status).toBe(400);
  });

  it("returns 409 JSON and a clear HTML banner when a sync is already running", async () => {
    const app = buildApp({
      vulnSyncImpls: {
        kev: async () => {
          throw new VulnSyncAlreadyRunningError("kev");
        },
      },
    });
    const json = await request(app).post("/admin/v1/vuln-sync/kev");
    expect(json.status).toBe(409);
    expect(json.body.outcomes[0].code).toBe("already_running");

    const html = await request(app).post("/admin/v1/vuln-sync/kev").set("Accept", "text/html");
    expect(html.status).toBe(302);
    const page = await request(app).get(html.headers.location);
    expect(page.text).toContain("kev sync is already running");
  });

  // WAL-UX: a browser form post to /vuln-backfill used to navigate to a raw JSON body —
  // a dead end for operators. Browser requests now redirect back with a banner; API
  // clients keep the 202/409 JSON contract.
  it("redirects an HTML backfill post back to the explorer with a job banner", async () => {
    const app = buildApp();
    const res = await request(app)
      .post("/admin/v1/vuln-backfill")
      .set("Accept", "text/html; charset=utf-8");
    expect(res.status).toBe(303);
    const location = new URL(res.headers.location, "http://x");
    expect(location.pathname).toBe("/admin/v1/vulns");
    expect(location.searchParams.get("backfill_started")).toBeTruthy();

    const page = await request(app).get(res.headers.location);
    expect(page.text).toMatch(
      /backfill job <a href="\/admin\/v1\/vuln-backfill\/\d+">#\d+<\/a> queued/,
    );
  });

  it("keeps the JSON contract for API backfill posts (202 + status_url)", async () => {
    const res = await request(buildApp()).post("/admin/v1/vuln-backfill");
    expect(res.status).toBe(202);
    expect(res.body.status_url).toMatch(/\/admin\/v1\/vuln-backfill\/\d+/);
    expect(res.body.job.status).toBe("queued");
  });

  it("shows a friendly banner when an HTML backfill post hits already-running", async () => {
    const app = buildApp({
      startVulnBackfill: async () => ({ alreadyRunning: true }),
    });
    const res = await request(app)
      .post("/admin/v1/vuln-backfill")
      .set("Accept", "text/html; charset=utf-8");
    expect(res.status).toBe(303);
    const page = await request(app).get(res.headers.location);
    expect(page.text).toContain("backfill is already running");
  });

  // WAL-71: the per-package backfill button posts an HTML form, not JSON. A dropped body here
  // does not fail loudly — `startVulnBackfill(undefined, undefined)` is a *valid* call meaning
  // "backfill every package", so the button would quietly walk all of them.
  it("carries the package scope from an urlencoded form post", async () => {
    const seen: Array<string | undefined> = [];
    const app = buildApp({
      startVulnBackfill: async (_since, packageName) => {
        seen.push(packageName);
        return {
          job: {
            id: 7,
            status: "queued" as const,
            since_date: null,
            cpe_pairs_total: 1,
            cpe_pairs_done: 0,
            error_message: null,
            execution_name: "test:7",
            started_at: null,
            finished_at: null,
            created_at: new Date(),
            package_name: "vscode",
          },
        };
      },
    });

    const res = await request(app)
      .post("/admin/v1/vuln-backfill")
      .set("Accept", "text/html; charset=utf-8")
      .type("form")
      .send("package=vscode&since=&return_version=1.135.0");

    expect(seen).toEqual(["vscode"]);
    const location = new URL(res.headers.location, "http://x");
    // The operator started this from a package's own view; the redirect has to land back on it.
    expect(location.searchParams.get("product")).toBe("vscode");
    expect(location.searchParams.get("version")).toBe("1.135.0");
  });

  it("returns the operator to the package view when a backfill is already running", async () => {
    const app = buildApp({ startVulnBackfill: async () => ({ alreadyRunning: true }) });

    const res = await request(app)
      .post("/admin/v1/vuln-backfill")
      .set("Accept", "text/html; charset=utf-8")
      .type("form")
      .send("package=vscode&return_version=1.135.0");

    const location = new URL(res.headers.location, "http://x");
    expect(location.searchParams.get("product")).toBe("vscode");
    expect(location.searchParams.get("sync_error")).toMatch(/already running/);
  });

  it("offers a package-scoped backfill on a resolved product page", async () => {
    const page = await request(buildApp()).get("/admin/v1/vulns?product=openjdk&version=11.0.2");
    expect(page.text).toContain('name="package" value="openjdk"');
    expect(page.text).toContain('name="return_version" value="11.0.2"');
    expect(page.text).toContain("Backfill this package");
  });

  it("surfaces an invalid-since error as a banner for HTML, 400 JSON for API", async () => {
    const app = buildApp();
    const html = await request(app)
      .post("/admin/v1/vuln-backfill")
      .set("Accept", "text/html; charset=utf-8")
      .send({ since: "not-a-date" });
    expect(html.status).toBe(303);
    const page = await request(app).get(html.headers.location);
    expect(page.text).toMatch(/since/i);

    const json = await request(app).post("/admin/v1/vuln-backfill").send({ since: "not-a-date" });
    expect(json.status).toBe(400);
    expect(json.body.error).toMatch(/since/i);
  });
});

describe("per-version CVE badges on package detail page", () => {
  // Uses a real configured package (openjdk) so it appears in the admin router.
  const CVE = "CVE-2099-7000";
  const V_AFFECTED = "11.0.2";
  const V_FIXED = "21.0.1";
  let appPool: Pool;

  beforeAll(async () => {
    appPool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    await appPool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await appPool.query(
      `DELETE FROM versions WHERE package_name = 'openjdk' AND version = ANY($1)`,
      [[V_AFFECTED, V_FIXED]],
    );
    await upsertPackage(appPool, {
      name: "openjdk",
      display_name: "Eclipse Temurin OpenJDK",
      vendor: "Eclipse Foundation",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(appPool, {
      packageName: "openjdk",
      aliases: ["openjdk", "temurin"],
      cpes: [{ cpe_vendor: "oracle", cpe_product: "openjdk", is_primary: true }],
      osvEcosystem: null,
      osvName: null,
    });
    for (const [version, group] of [
      [V_AFFECTED, "11"],
      [V_FIXED, "21"],
    ] as const) {
      await insertVersion(appPool, {
        package_name: "openjdk",
        version,
        version_group: group,
        is_lts: true,
        version_sort: generateSortKey(version),
      });
    }
    await upsertCveFull(appPool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: 9.8,
      cvss_v3_vector: null,
      severity: "CRITICAL",
      description: "x",
      raw: { cve: { id: CVE } },
    });
    await insertAffects(appPool, {
      cve_id: CVE,
      package_name: "openjdk",
      version_start: null,
      version_start_excl: false,
      version_end: "20",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "20",
      source: "nvd",
      raw_cpe: "cpe:2.3:a:oracle:openjdk:*|<20",
    });
  });

  afterAll(async () => {
    // Fully remove the openjdk package we created so its oracle:openjdk CPE/aliases
    // don't leak into other test files (package delete cascades aliases/cpes/affects).
    await appPool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await appPool.query(`DELETE FROM versions WHERE package_name = 'openjdk'`);
    await appPool.query(`DELETE FROM packages WHERE name = 'openjdk'`);
    await appPool.end();
  });

  it("shows a coloured CVE badge on the affected cached version, none on the fixed one", async () => {
    const auth = testOperatorAuth();
    const app = createApp({ operatorAuth: auth.runtime });
    const res = await request(app)
      .get("/admin/v1/packages/openjdk")
      .set("authorization", `Bearer ${auth.bearer}`);
    expect(res.status).toBe(200);
    // Affected version links into the pre-filled explorer with a critical badge.
    expect(res.text).toMatch(/badge-vuln-crit/);
    expect(res.text).toContain(`/admin/v1/vulns?product=openjdk&version=11.0.2`);
    // The fixed version 21.0.1 must not carry a badge link.
    expect(res.text).not.toContain(`version=21.0.1`);
  });
});
