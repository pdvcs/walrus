import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { readFileSync } from "fs";
import { join } from "path";
import { Pool } from "pg";
import { runMigrations } from "../../../src/db/client.js";
import { upsertPackage } from "../../../src/db/queries/packages.js";
import { reconcilePackageVuln } from "../../../src/db/queries/package-aliases.js";
import { getSyncCursor } from "../../../src/db/queries/vuln-sync-state.js";
import { NvdClient, type NvdCveItem } from "../../../src/vuln/sync/nvd-client.js";
import {
  backfillNvd,
  extractAffects,
  extractCvss,
  ingestCveItems,
  incrementalNvdSync,
  MAX_NVD_DATE_WINDOW_MS,
  NVD_LASTMOD_LAG_MARGIN_MS,
} from "../../../src/vuln/sync/nvd-sync.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const FIXTURES = join(process.cwd(), "tests/fixtures/vuln");
const notepadFixture = JSON.parse(readFileSync(join(FIXTURES, "nvd-cves-notepad.json"), "utf8"));
const items: NvdCveItem[] = notepadFixture.vulnerabilities;
const fixtureCveIds: string[] = items.map((i) => i.cve.id);

const PKG = "test-npp";
const PKG2 = "test-npp2";

async function seedPackage(pool: Pool, name: string): Promise<void> {
  await upsertPackage(pool, {
    name,
    display_name: name,
    vendor: "Don Ho",
    description: null,
    website: null,
    config_hash: "h",
    enabled: true,
  });
  await reconcilePackageVuln(pool, {
    packageName: name,
    aliases: ["notepad++", "npp"],
    cpes: [{ cpe_vendor: "notepad-plus-plus", cpe_product: "notepad++", is_primary: true }],
    osvEcosystem: null,
    osvName: null,
  });
}

describe("extractCvss", () => {
  const withMetrics = (metrics: Record<string, unknown>): NvdCveItem =>
    ({ cve: { id: "CVE-0000-0000", metrics } }) as unknown as NvdCveItem;

  const v3 = (baseScore: number, baseSeverity: string) => [
    {
      type: "Primary",
      cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N", baseScore, baseSeverity },
    },
  ];
  // NVD puts v2's baseSeverity on the metric object, NOT inside cvssData.
  const v2 = (baseScore: number, baseSeverity: string) => [
    {
      type: "Primary",
      cvssData: { version: "2.0", vectorString: "AV:N/AC:M/Au:N/C:P/I:P/A:P", baseScore },
      baseSeverity,
    },
  ];
  // v4 keeps baseSeverity inside cvssData, like v3.
  const v4 = (baseScore: number, baseSeverity: string) => [
    {
      type: "Primary",
      cvssData: { version: "4.0", vectorString: "CVSS:4.0/AV:N", baseScore, baseSeverity },
    },
  ];

  it("prefers v3.1 for severity while still recording v2 alongside it", () => {
    const r = extractCvss(
      withMetrics({ cvssMetricV31: v3(9.8, "CRITICAL"), cvssMetricV2: v2(6.8, "MEDIUM") }),
    );
    expect(r.severity).toBe("CRITICAL");
    expect(r.severitySource).toBe("nvd-cvss-v3");
    expect(r.score).toBe(9.8);
    // v2 is kept even when v3 wins — the columns are independent.
    expect(r.v2Score).toBe(6.8);
    expect(r.v2Vector).toBe("AV:N/AC:M/Au:N/C:P/I:P/A:P");
  });

  it("falls back to v3.0 when v3.1 is absent", () => {
    const r = extractCvss(withMetrics({ cvssMetricV30: v3(7.5, "HIGH") }));
    expect(r.severity).toBe("HIGH");
    expect(r.severitySource).toBe("nvd-cvss-v3");
    expect(r.score).toBe(7.5);
  });

  it("falls back to v2 when no v3 metric exists — the gap this fixes", () => {
    const r = extractCvss(withMetrics({ cvssMetricV2: v2(4.3, "MEDIUM") }));
    expect(r.severity).toBe("MEDIUM");
    expect(r.severitySource).toBe("nvd-cvss-v2");
    // v3 columns stay null: a v2 score is NOT a v3 score.
    expect(r.score).toBeNull();
    expect(r.vector).toBeNull();
    expect(r.v2Score).toBe(4.3);
  });

  it("reads v2 baseSeverity from the metric object, not cvssData", () => {
    const metric = [
      { type: "Primary", cvssData: { version: "2.0", baseScore: 7.5 }, baseSeverity: "HIGH" },
    ];
    expect(extractCvss(withMetrics({ cvssMetricV2: metric })).severity).toBe("HIGH");
  });

  it("reads a v4-only CVE — the gap that left Deferred-backlog scores invisible", () => {
    const r = extractCvss(withMetrics({ cvssMetricV40: v4(9.5, "CRITICAL") }));
    expect(r.severity).toBe("CRITICAL");
    expect(r.severitySource).toBe("nvd-cvss-v4");
    expect(r.v4Score).toBe(9.5);
    expect(r.v4Vector).toBe("CVSS:4.0/AV:N");
    // v3 columns stay null: a v4 score is NOT a v3 score.
    expect(r.score).toBeNull();
  });

  it("prefers v3 severity over v4 but records both scores", () => {
    const r = extractCvss(
      withMetrics({ cvssMetricV31: v3(8.8, "HIGH"), cvssMetricV40: v4(9.3, "CRITICAL") }),
    );
    expect(r.severitySource).toBe("nvd-cvss-v3");
    expect(r.severity).toBe("HIGH");
    expect(r.score).toBe(8.8);
    expect(r.v4Score).toBe(9.3);
  });

  it("prefers v4 severity over v2 (v4 shares v3's bands; v2 has no CRITICAL)", () => {
    const r = extractCvss(
      withMetrics({ cvssMetricV40: v4(9.1, "CRITICAL"), cvssMetricV2: v2(9.8, "HIGH") }),
    );
    expect(r.severitySource).toBe("nvd-cvss-v4");
    expect(r.severity).toBe("CRITICAL");
    expect(r.v2Score).toBe(9.8);
  });

  it("returns all-null with no severity source when there are no metrics", () => {
    const r = extractCvss(withMetrics({}));
    expect(r).toEqual({
      score: null,
      vector: null,
      v4Score: null,
      v4Vector: null,
      v2Score: null,
      v2Vector: null,
      severity: null,
      severitySource: null,
    });
  });

  it("prefers the Primary provider over a secondary one", () => {
    const metrics = {
      cvssMetricV31: [
        { type: "Secondary", cvssData: { baseScore: 5.0, baseSeverity: "MEDIUM" } },
        { type: "Primary", cvssData: { baseScore: 9.1, baseSeverity: "CRITICAL" } },
      ],
    };
    expect(extractCvss(withMetrics(metrics)).score).toBe(9.1);
  });

  it("parses the real fixture CVE that carries both v3.1 and v2", () => {
    const item = items.find((i) => i.cve.id === "CVE-2017-8803")!;
    const r = extractCvss(item);
    expect(r.severitySource).toBe("nvd-cvss-v3");
    expect(r.v2Score).toBe(6.8);
    expect(r.v2Vector).toBe("AV:N/AC:M/Au:N/C:P/I:P/A:P");
  });
});

describe("nvd-sync ingestion", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [fixtureCveIds]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [fixtureCveIds]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'nvd-cve'`);
    await seedPackage(pool, PKG);
  });

  it("ingests fixture CVEs and produces affects rows with correct bounds and fixed_in", async () => {
    const counts = await ingestCveItems(pool, items);
    expect(counts.cves).toBe(items.length);
    expect(counts.affects).toBeGreaterThan(0);

    // CVE-2019-16294: notepad++ versionEndExcluding 7.7 → fixed_in 7.7, end-exclusive.
    const { rows } = await pool.query(
      `SELECT version_end, version_end_excl, fixed_in, source FROM cve_affects
       WHERE cve_id = 'CVE-2019-16294' AND package_name = $1`,
      [PKG],
    );
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const npp = rows.find((r) => r.version_end === "7.7");
    expect(npp).toBeTruthy();
    expect(npp.version_end_excl).toBe(true);
    expect(npp.fixed_in).toBe("7.7");
    expect(npp.source).toBe("nvd");
  });

  it("skips untracked CPEs (scintilla, hex_editor) and counts them", async () => {
    const counts = await ingestCveItems(pool, items);
    expect(counts.skippedCpes).toBeGreaterThan(0);
    // No affects rows for a CPE we don't track.
    const { rows } = await pool.query(`SELECT raw_cpe FROM cve_affects WHERE package_name = $1`, [
      PKG,
    ]);
    expect(rows.every((r) => r.raw_cpe.includes("notepad"))).toBe(true);
  });

  it("is idempotent: re-ingesting leaves affects row count unchanged", async () => {
    await ingestCveItems(pool, items);
    const before = await affectsCount(pool, PKG);
    await ingestCveItems(pool, items);
    const after = await affectsCount(pool, PKG);
    expect(after).toBe(before);
  });

  it("rebuilds (not appends) a modified CVE's affects rows", async () => {
    await ingestCveItems(pool, items);
    const before = await affectsCount(pool, PKG);

    // Re-ingest one CVE with its configuration stripped → its nvd affects vanish.
    const stripped: NvdCveItem = {
      cve: { ...items.find((i) => i.cve.id === "CVE-2019-16294")!.cve, configurations: [] },
    };
    await ingestCveItems(pool, [stripped]);

    const rowsForCve = await pool.query(
      `SELECT count(*)::int AS n FROM cve_affects WHERE cve_id = 'CVE-2019-16294' AND package_name = $1`,
      [PKG],
    );
    expect(rowsForCve.rows[0].n).toBe(0);
    expect(await affectsCount(pool, PKG)).toBeLessThan(before);
  });

  it("produces affects rows for every package sharing a CPE pair", async () => {
    await seedPackage(pool, PKG2);
    await ingestCveItems(pool, items);
    const a = await affectsCount(pool, PKG);
    const b = await affectsCount(pool, PKG2);
    expect(a).toBeGreaterThan(0);
    expect(b).toBe(a);
  });

  /**
   * Stands in for `NvdClient.cvePages`, which `backfillNvd` consumes instead of the accumulating
   * the accumulating `cvesForCpe` since WAL-97, which no longer exists. One call per (CPE pair, publication window), and the pair now travels
   * inside the params object as `virtualMatchString` rather than as a separate first argument.
   */
  const pagesOf = (vulnerabilities: NvdCveItem[] = []) =>
    vi.fn(async function* () {
      yield {
        resultsPerPage: vulnerabilities.length,
        startIndex: 0,
        totalResults: vulnerabilities.length,
        vulnerabilities,
      };
    });

  const matchStringsOf = (m: ReturnType<typeof pagesOf>) =>
    m.mock.calls.map((c) => (c[0] as { virtualMatchString: string }).virtualMatchString);

  it("uses paired bounded publication windows for a dated backfill", async () => {
    const cvePages = pagesOf();
    const nvd = { cvePages } as unknown as NvdClient;

    await backfillNvd(pool, nvd, {
      since: "2024-01-01",
      now: new Date("2024-07-01T12:00:00.000Z"),
    });

    expect(cvePages).toHaveBeenCalledTimes(2);
    for (const [params] of cvePages.mock.calls) {
      expect(params).toHaveProperty("pubStartDate");
      expect(params).toHaveProperty("pubEndDate");
    }
    expect((cvePages.mock.calls[0][0] as Record<string, string>).pubStartDate).toBe(
      "2024-01-01T00:00:00.000Z",
    );
    expect((cvePages.mock.calls[1][0] as Record<string, string>).pubEndDate).toBe(
      "2024-07-01T12:00:00.000Z",
    );
  });

  describe("targeted backfill (--package)", () => {
    // A second package with a DIFFERENT pair, so scoping is observable.
    const SCOPED = "test-scoped-pkg";

    async function seedScoped(): Promise<void> {
      await upsertPackage(pool, {
        name: SCOPED,
        display_name: SCOPED,
        vendor: "v",
        description: null,
        website: null,
        config_hash: "h",
        enabled: true,
      });
      await reconcilePackageVuln(pool, {
        packageName: SCOPED,
        aliases: ["scoped"],
        cpes: [{ cpe_vendor: "acme", cpe_product: "widget", is_primary: true }],
        osvEcosystem: null,
        osvName: null,
      });
    }

    beforeEach(async () => {
      await seedPackage(pool, PKG);
      await seedScoped();
    });

    afterAll(async () => {
      await pool.query(`DELETE FROM packages WHERE name = $1`, [SCOPED]);
    });

    it("walks only the named package's CPE pairs", async () => {
      const cvePages = pagesOf();
      const nvd = { cvePages } as unknown as NvdClient;

      await backfillNvd(pool, nvd, { packageName: SCOPED });

      expect(cvePages).toHaveBeenCalledTimes(1);
      expect(matchStringsOf(cvePages)[0]).toBe("cpe:2.3:a:acme:widget");
    });

    it("walks every pair when no package is given", async () => {
      const cvePages = pagesOf();
      const nvd = { cvePages } as unknown as NvdClient;

      await backfillNvd(pool, nvd, {});

      const matchStrings = matchStringsOf(cvePages);
      expect(matchStrings).toContain("cpe:2.3:a:acme:widget");
      expect(matchStrings.length).toBeGreaterThan(1);
    });

    it("does NOT advance the nvd-cve cursor (a one-package walk proves nothing global)", async () => {
      const nvd = { cvePages: pagesOf() } as unknown as NvdClient;
      const before = await getSyncCursor(pool, "nvd-cve");

      await backfillNvd(pool, nvd, { packageName: SCOPED });

      expect(await getSyncCursor(pool, "nvd-cve")).toBe(before);
    });

    it("still advances the cursor for a full backfill", async () => {
      const nvd = { cvePages: pagesOf() } as unknown as NvdClient;
      const now = new Date("2025-06-01T00:00:00.000Z");

      await backfillNvd(pool, nvd, { now });

      expect(await getSyncCursor(pool, "nvd-cve")).toBe(now.toISOString());
    });

    it("leaves the cursor untouched when a targeted backfill fails", async () => {
      // First `next()` rejects — an upstream failure on the first page.
      const nvd = {
        cvePages: vi.fn(() => ({
          [Symbol.asyncIterator]: () => ({
            next: () => Promise.reject(new Error("upstream boom")),
          }),
        })),
      } as unknown as NvdClient;
      const before = await getSyncCursor(pool, "nvd-cve");

      await expect(backfillNvd(pool, nvd, { packageName: SCOPED })).rejects.toThrow("boom");

      expect(await getSyncCursor(pool, "nvd-cve")).toBe(before);
    });

    it("attributes a shared pair to every package tracking it, even when scoped", async () => {
      // PKG2 shares PKG's pair. Backfilling PKG alone must still record PKG2's
      // rows — the CVE genuinely affects it.
      await seedPackage(pool, PKG2);
      const nvd = { cvePages: pagesOf(items) } as unknown as NvdClient;

      await backfillNvd(pool, nvd, { packageName: PKG });

      expect(await affectsCount(pool, PKG2)).toBeGreaterThan(0);
    });
  });

  it("deliberately flattens NVD AND configurations to vulnerable application CPEs", () => {
    const andItem = items.find((item) =>
      item.cve.configurations?.some((configuration) =>
        configuration.nodes.some((node) => node.operator === "OR"),
      ),
    )!;
    expect(
      andItem.cve.configurations?.some((configuration) => configuration.operator === "AND"),
    ).toBe(true);

    const result = extractAffects(andItem, new Map([["mh-nexus:hex_editor", [PKG]]]));

    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({ package_name: PKG, exact_version: "0.9.5" });
  });

  describe("incrementalNvdSync + cursor (msw)", () => {
    const server = setupServer();
    beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
    afterAll(() => server.close());

    /** Capture the lastMod window of each /cves request, deduped across pagination pages. */
    function captureWindows(): Array<{ start: string; end: string }> {
      const seen: Array<{ start: string; end: string }> = [];
      server.events.on("request:start", ({ request }) => {
        const url = new URL(request.url);
        if (url.pathname !== "/rest/json/cves/2.0") return;
        const s = url.searchParams.get("lastModStartDate");
        const e = url.searchParams.get("lastModEndDate");
        if (
          s &&
          e &&
          (seen.length === 0 ||
            seen[seen.length - 1].start !== s ||
            seen[seen.length - 1].end !== e)
        ) {
          seen.push({ start: s, end: e });
        }
      });
      return seen;
    }

    function mockPages(payload: unknown) {
      server.use(
        http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", ({ request }) => {
          // Only the first page has content; second page (startIndex beyond total) empty.
          if (Number(new URL(request.url).searchParams.get("startIndex")) > 0) {
            return HttpResponse.json({
              resultsPerPage: 0,
              startIndex: Number(new URL(request.url).searchParams.get("startIndex")),
              totalResults: items.length,
              vulnerabilities: [],
            });
          }
          return HttpResponse.json(payload);
        }),
      );
    }

    it("advances the cursor on success", async () => {
      mockPages(notepadFixture);
      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, async () => {});
      const counts = await incrementalNvdSync(pool, nvd, {});
      expect(counts.affects).toBeGreaterThan(0);
      const cursor = await getSyncCursor(pool, "nvd-cve");
      expect(cursor).not.toBeNull();
    });

    it("starts each window a lag margin before the cursor, and advances to the window end", async () => {
      // WAL-47: NVD's lastMod index lags, so abutting windows permanently skip CVEs
      // indexed just after a run. The next window must re-cover [cursor - margin].
      const now = new Date("2026-08-26T21:00:00.000Z");
      const cursorAt = new Date(now.getTime() - 3_600_000); // previous run 1h ago
      await pool.query(
        `INSERT INTO vuln_sync_state (source, cursor, last_run, last_ok)
         VALUES ('nvd-cve', $1, now(), true)`,
        [cursorAt.toISOString()],
      );
      mockPages(notepadFixture);
      const windows = captureWindows();
      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, async () => {});

      await incrementalNvdSync(pool, nvd, { now });
      expect(windows[0].start).toBe(
        new Date(cursorAt.getTime() - NVD_LASTMOD_LAG_MARGIN_MS).toISOString(),
      );
      expect(windows[0].end).toBe(now.toISOString());
      const advancedTo = new Date((await getSyncCursor(pool, "nvd-cve"))!);

      // The following run overlaps this one's tail instead of abutting it.
      const next = new Date(advancedTo.getTime() + 2 * 3_600_000);
      await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'nvd-cve'`);
      await pool.query(
        `INSERT INTO vuln_sync_state (source, cursor, last_run, last_ok)
         VALUES ('nvd-cve', $1, now(), true)`,
        [advancedTo.toISOString()],
      );
      await incrementalNvdSync(pool, nvd, { now: next });
      expect(windows[1].start).toBe(
        new Date(advancedTo.getTime() - NVD_LASTMOD_LAG_MARGIN_MS).toISOString(),
      );
      expect(windows[1].end).toBe(next.toISOString());
    });

    it("keeps the full lookback on a fresh DB (no previous window to bridge)", async () => {
      const now = new Date("2026-08-26T21:00:00.000Z");
      mockPages(notepadFixture);
      const windows = captureWindows();
      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, async () => {});

      await incrementalNvdSync(pool, nvd, { now });
      expect(windows[0].start).toBe(new Date(now.getTime() - MAX_NVD_DATE_WINDOW_MS).toISOString());
      expect(windows[0].end).toBe(now.toISOString());
    });

    it("re-ingests the overlap without duplicating affects rows", async () => {
      const cve = items.find((item) => item.cve.id === "CVE-2019-16294")!;
      server.use(
        http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", ({ request }) => {
          const startIndex = Number(new URL(request.url).searchParams.get("startIndex"));
          // Same item on every query — both runs see identical data across the overlap.
          return HttpResponse.json({
            resultsPerPage: startIndex === 0 ? 1 : 0,
            startIndex,
            totalResults: 1,
            vulnerabilities: startIndex === 0 ? [cve] : [],
          });
        }),
      );

      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, async () => {});
      const t0 = new Date("2026-08-26T20:00:00.000Z");
      await incrementalNvdSync(pool, nvd, { now: t0 });
      const first = await affectsCount(pool, PKG);
      expect(first).toBeGreaterThan(0);

      // Second run starts inside the first's coverage (cursor - margin < t0).
      await incrementalNvdSync(pool, nvd, { now: new Date(t0.getTime() + 600_000) });
      expect(await affectsCount(pool, PKG)).toBe(first);
    });

    it("removes obsolete affects for a known CVE that no longer matches a tracked CPE", async () => {
      const original = items.find((item) => item.cve.id === "CVE-2019-16294")!;
      await ingestCveItems(pool, [original]);
      expect(await affectsCount(pool, PKG)).toBeGreaterThan(0);

      const modified: NvdCveItem = {
        cve: { ...original.cve, configurations: [] },
      };
      server.use(
        http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", ({ request }) => {
          const startIndex = Number(new URL(request.url).searchParams.get("startIndex"));
          return HttpResponse.json({
            resultsPerPage: startIndex === 0 ? 1 : 0,
            startIndex,
            totalResults: 1,
            vulnerabilities: startIndex === 0 ? [modified] : [],
          });
        }),
      );

      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, async () => {});
      const counts = await incrementalNvdSync(pool, nvd);

      expect(counts.cves).toBe(1);
      expect(await affectsCount(pool, PKG)).toBe(0);
    });

    it("leaves last_ok=false and preserves the old cursor on failure", async () => {
      // Seed a known-good cursor.
      await pool.query(
        `INSERT INTO vuln_sync_state (source, cursor, last_run, last_ok)
         VALUES ('nvd-cve', '2020-01-01T00:00:00.000Z', now(), true)`,
      );
      server.use(
        http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", () =>
          HttpResponse.json({}, { status: 500 }),
        ),
      );
      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1, maxRetries: 1 }, async () => {});
      await expect(incrementalNvdSync(pool, nvd, {})).rejects.toThrow();

      const { rows } = await pool.query(
        `SELECT cursor, last_ok FROM vuln_sync_state WHERE source = 'nvd-cve'`,
      );
      expect(rows[0].cursor).toBe("2020-01-01T00:00:00.000Z"); // preserved
      expect(rows[0].last_ok).toBe(false);
    });
  });
});

async function affectsCount(pool: Pool, pkg: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1`,
    [pkg],
  );
  return rows[0].n;
}

describe("CPE version NA vs ANY (WAL-69)", () => {
  const LOOKUP = new Map([["microsoft:visual_studio_code", ["vscode"]]]);

  /** Shaped after the real CVE-2024-43488 configuration: NA version, no range bounds. */
  function itemWithVersion(criteriaVersion: string, extra: Record<string, unknown> = {}) {
    return {
      cve: {
        id: "CVE-2024-43488",
        configurations: [
          {
            nodes: [
              {
                operator: "OR",
                negate: false,
                cpeMatch: [
                  {
                    vulnerable: true,
                    criteria: `cpe:2.3:a:microsoft:visual_studio_code:${criteriaVersion}:*:*:*:*:*:*:*`,
                    ...extra,
                  },
                ],
              },
            ],
          },
        ],
      },
    } as unknown as Parameters<typeof extractAffects>[0];
  }

  it("flags an NA version without dropping the row", () => {
    // Nothing is skipped at ingest: the advisory stays on the record, it just stops
    // claiming to describe every version.
    const { rows, skippedCpes } = extractAffects(itemWithVersion("-"), LOOKUP);

    expect(skippedCpes).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      package_name: "vscode",
      version_na: true,
      exact_version: null,
      version_start: null,
      version_end: null,
      raw_cpe: "cpe:2.3:a:microsoft:visual_studio_code:-:*:*:*:*:*:*:*",
    });
  });

  it("does not flag ANY, with or without bounds", () => {
    expect(extractAffects(itemWithVersion("*"), LOOKUP).rows[0]).toMatchObject({
      version_na: false,
      exact_version: null,
    });

    const bounded = extractAffects(
      itemWithVersion("*", { versionEndExcluding: "1.104.0" }),
      LOOKUP,
    );
    expect(bounded.rows[0]).toMatchObject({
      version_na: false,
      version_end: "1.104.0",
      fixed_in: "1.104.0",
    });
  });

  it("does not flag a concrete version", () => {
    expect(extractAffects(itemWithVersion("1.104.2"), LOOKUP).rows[0]).toMatchObject({
      version_na: false,
      exact_version: "1.104.2",
    });
  });
});
