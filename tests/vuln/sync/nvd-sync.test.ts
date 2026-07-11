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
  ingestCveItems,
  incrementalNvdSync,
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

  it("uses paired bounded publication windows for a dated backfill", async () => {
    const cvesForCpe = vi.fn().mockResolvedValue([]);
    const nvd = { cvesForCpe } as unknown as NvdClient;

    await backfillNvd(pool, nvd, {
      since: "2024-01-01",
      now: new Date("2024-07-01T12:00:00.000Z"),
    });

    expect(cvesForCpe).toHaveBeenCalledTimes(2);
    for (const [, params] of cvesForCpe.mock.calls) {
      expect(params).toHaveProperty("pubStartDate");
      expect(params).toHaveProperty("pubEndDate");
    }
    expect(cvesForCpe.mock.calls[0][1].pubStartDate).toBe("2024-01-01T00:00:00.000Z");
    expect(cvesForCpe.mock.calls[1][1].pubEndDate).toBe("2024-07-01T12:00:00.000Z");
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

    it("advances the cursor on success", async () => {
      server.use(
        http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", ({ request }) => {
          const url = new URL(request.url);
          // Only the first page has content; second page (startIndex beyond total) empty.
          if (Number(url.searchParams.get("startIndex")) > 0) {
            return HttpResponse.json({
              resultsPerPage: 0,
              startIndex: Number(url.searchParams.get("startIndex")),
              totalResults: items.length,
              vulnerabilities: [],
            });
          }
          return HttpResponse.json(notepadFixture);
        }),
      );
      const nvd = new NvdClient({ apiKey: "k", backoffBaseMs: 1 }, async () => {});
      const counts = await incrementalNvdSync(pool, nvd, {});
      expect(counts.affects).toBeGreaterThan(0);
      const cursor = await getSyncCursor(pool, "nvd-cve");
      expect(cursor).not.toBeNull();
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
