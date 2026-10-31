import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { readFileSync } from "fs";
import { join } from "path";
import { Pool } from "pg";
import { runMigrations } from "../../../src/db/client.js";
import { upsertCveFull, getCveById } from "../../../src/db/queries/cves.js";
import { getSyncCursor } from "../../../src/db/queries/vuln-sync-state.js";
import { applyKev, kevSync, type KevCatalog } from "../../../src/vuln/sync/kev-sync.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const catalog = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vuln/kev-sample.json"), "utf8"),
) as KevCatalog;

// One KEV entry we'll pre-ingest as a tracked CVE, plus a control that stays absent.
const TRACKED = "CVE-2025-15556"; // present in the KEV fixture
const ALL_KEV_IDS = catalog.vulnerabilities.map((v) => v.cveID);
const CONTROL = "CVE-2099-9999"; // not in the KEV fixture

async function seedCve(pool: Pool, id: string): Promise<void> {
  await upsertCveFull(pool, {
    id,
    published_at: null,
    modified_at: null,
    cvss_v3_score: null,
    cvss_v3_vector: null,
    severity: "HIGH",
    description: null,
    raw: { cve: { id } },
  });
}

describe("kev-sync", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [[...ALL_KEV_IDS, CONTROL]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [[...ALL_KEV_IDS, CONTROL]]);
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'kev'`);
  });

  it("flags exactly the tracked intersection; unknown KEV entries are skipped", async () => {
    await seedCve(pool, TRACKED); // only this KEV CVE is tracked
    const res = await applyKev(pool, catalog);
    expect(res.flagged).toBe(1);
    expect(res.skippedUnknown).toBe(catalog.vulnerabilities.length - 1);

    const cve = await getCveById(pool, TRACKED);
    expect(cve!.is_kev).toBe(true);
    expect(cve!.kev_added_at).not.toBeNull();
  });

  it("is idempotent across re-runs", async () => {
    await seedCve(pool, TRACKED);
    await applyKev(pool, catalog);
    const first = await getCveById(pool, TRACKED);
    await applyKev(pool, catalog);
    const second = await getCveById(pool, TRACKED);
    expect(second!.is_kev).toBe(true);
    expect(second!.kev_added_at?.getTime()).toBe(first!.kev_added_at?.getTime());
  });

  it("clears the KEV flag on a CVE that left the catalog", async () => {
    // A CVE flagged as KEV but absent from the catalog should be cleared.
    await seedCve(pool, CONTROL);
    await pool.query(`UPDATE cves SET is_kev = TRUE, kev_added_at = '2020-01-01' WHERE id = $1`, [
      CONTROL,
    ]);
    await applyKev(pool, catalog);
    const cve = await getCveById(pool, CONTROL);
    expect(cve!.is_kev).toBe(false);
    expect(cve!.kev_added_at).toBeNull();
  });

  // WAL-52: CISA has never published a zero-entry catalog, so an empty-but-parseable
  // payload is upstream breakage (JSON error body, truncated feed). Mass-clearing every
  // flag on it would hide confirmed-exploited CVEs from badges and counts for a week.
  it("refuses to apply an empty catalog instead of clearing every flag", async () => {
    await seedCve(pool, TRACKED);
    await applyKev(pool, catalog); // establish a flagged state first
    expect((await getCveById(pool, TRACKED))!.is_kev).toBe(true);

    const empty: KevCatalog = {
      catalogVersion: "2026.08.27",
      vulnerabilities: [],
    };
    await expect(applyKev(pool, empty)).rejects.toThrow("no vulnerabilities");

    // The previously flagged CVE keeps its flag — nothing was written.
    expect((await getCveById(pool, TRACKED))!.is_kev).toBe(true);
  });

  describe("kevSync (msw download)", () => {
    const server = setupServer();
    beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
    afterAll(() => server.close());

    it("downloads the catalog, flags, and records the cursor", async () => {
      await seedCve(pool, TRACKED);
      server.use(
        http.get(
          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
          () => HttpResponse.json(catalog),
        ),
      );
      const res = await kevSync(pool);
      expect(res.flagged).toBe(1);
      expect(await getSyncCursor(pool, "kev")).toBe(catalog.catalogVersion);
    });

    it("fails the sync (and marks last_ok=false) when the download yields an empty catalog", async () => {
      await seedCve(pool, TRACKED);
      server.use(
        http.get(
          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
          () => HttpResponse.json({ catalogVersion: "x", vulnerabilities: [] }),
        ),
      );
      await expect(kevSync(pool)).rejects.toThrow("no vulnerabilities");
      const { rows } = await pool.query(`SELECT last_ok FROM vuln_sync_state WHERE source = 'kev'`);
      expect(rows[0].last_ok).toBe(false);
      expect(await getSyncCursor(pool, "kev")).toBeNull();
    });

    it("rejects a download whose body is not a recognizable catalog", async () => {
      server.use(
        http.get(
          "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
          () => HttpResponse.json({ error: "rate limited" }),
        ),
      );
      await expect(kevSync(pool)).rejects.toThrow("not a recognizable catalog");
    });

    it("applies an abort timeout to the KEV request", async () => {
      await seedCve(pool, TRACKED);
      const fetchFn = vi.fn().mockResolvedValue(
        new Response(JSON.stringify(catalog), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );

      await kevSync(pool, fetchFn);

      expect((fetchFn.mock.calls[0][1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
    });
  });
});
