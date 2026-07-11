import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { readFileSync } from "fs";
import { join } from "path";
import { Pool } from "pg";
import { runMigrations } from "../../../src/db/client.js";
import { upsertPackage } from "../../../src/db/queries/packages.js";
import { reconcilePackageVuln } from "../../../src/db/queries/package-aliases.js";
import {
  upsertCveFull,
  insertAffects,
  getCveById,
  listAffectsWithCveForPackage,
} from "../../../src/db/queries/cves.js";
import { getSyncCursor } from "../../../src/db/queries/vuln-sync-state.js";
import { osvSyncAll, queryOsvPackage, type OsvVuln } from "../../../src/vuln/sync/osv-sync.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const osvFixture = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vuln/osv-go-stdlib.json"), "utf8"),
) as { vulns: OsvVuln[] };
const osvCveIds = osvFixture.vulns
  .map((v) => (v.id.match(/^CVE-/) ? v.id : v.aliases?.find((a) => /^CVE-\d{4}-\d+$/.test(a))))
  .filter((x): x is string => Boolean(x));

const PKG = "test-go-osv";
const PKG2 = "test-go-osv-2";
const BOTH = "CVE-2023-39318"; // present in the OSV fixture
const OSV_ONLY = "CVE-2023-39319"; // present in the OSV fixture, not pre-ingested

describe("osv-sync", () => {
  let pool: Pool;
  const server = setupServer();

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    server.listen({ onUnhandledRequest: "error" });
  });

  afterAll(async () => {
    server.close();
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [osvCveIds]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.end();
  });

  beforeEach(async () => {
    server.resetHandlers();
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [osvCveIds]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'osv'`);
    await upsertPackage(pool, {
      name: PKG,
      display_name: "Go",
      vendor: "Google",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG,
      aliases: ["go", "golang"],
      cpes: [{ cpe_vendor: "golang", cpe_product: "go", is_primary: true }],
      osvEcosystem: "Go",
      osvName: "stdlib",
    });
    server.use(
      http.post("https://api.osv.dev/v1/query", () =>
        HttpResponse.json({ vulns: osvFixture.vulns }),
      ),
    );
  });

  it("creates osv-sourced affects rows and stub CVEs for OSV-only CVEs", async () => {
    const res = await osvSyncAll(pool);
    expect(res.packages).toBe(1);
    expect(res.affectsUpserted).toBeGreaterThan(0);

    const affects = await listAffectsWithCveForPackage(pool, PKG);
    expect(affects.some((a) => a.source === "osv")).toBe(true);

    // An OSV-only CVE exists as a stub row.
    const stub = await getCveById(pool, OSV_ONLY);
    expect(stub).not.toBeNull();
    expect((stub!.raw as { osvStub?: boolean }).osvStub).toBe(true);

    expect(await getSyncCursor(pool, "osv")).not.toBeNull();
  });

  it("applies an abort timeout to OSV requests", async () => {
    const fetchFn = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ vulns: [] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    await queryOsvPackage("Go", "stdlib", fetchFn);
    expect((fetchFn.mock.calls[0][1] as RequestInit).signal).toBeInstanceOf(AbortSignal);
  });

  it("merges sources for a CVE present in both NVD and OSV", async () => {
    // Pre-ingest CVE-2023-39318 as an NVD row for this package.
    await upsertCveFull(pool, {
      id: BOTH,
      published_at: null,
      modified_at: null,
      cvss_v3_score: 7.5,
      cvss_v3_vector: null,
      severity: "HIGH",
      description: "nvd full record",
      raw: { cve: { id: BOTH } },
    });
    await insertAffects(pool, {
      cve_id: BOTH,
      package_name: PKG,
      version_start: null,
      version_start_excl: false,
      version_end: "1.20.8",
      version_end_excl: true,
      exact_version: null,
      fixed_in: "1.20.8",
      source: "nvd",
      raw_cpe: "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*|<1.20.8",
    });

    await osvSyncAll(pool);

    const { rows } = await pool.query<{ source: string }>(
      `SELECT DISTINCT source FROM cve_affects WHERE cve_id = $1 AND package_name = $2 ORDER BY source`,
      [BOTH, PKG],
    );
    expect(rows.map((r) => r.source)).toEqual(["nvd", "osv"]);

    // The stub upsert must NOT clobber the full NVD record.
    const cve = await getCveById(pool, BOTH);
    expect(cve!.description).toBe("nvd full record");
  });

  it("is idempotent: re-running OSV sync does not duplicate affects rows", async () => {
    await osvSyncAll(pool);
    const before = await osvAffectsCount(pool, PKG);
    await osvSyncAll(pool);
    const after = await osvAffectsCount(pool, PKG);
    expect(after).toBe(before);
  });

  it("retains OSV rows for two packages that share a CVE", async () => {
    await upsertPackage(pool, {
      name: PKG2,
      display_name: "Go 2",
      vendor: "Google",
      description: null,
      website: null,
      config_hash: "h2",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: PKG2,
      aliases: ["go 2"],
      cpes: [],
      osvEcosystem: "Go",
      osvName: "stdlib",
    });

    await osvSyncAll(pool);

    expect(await osvAffectsCount(pool, PKG)).toBeGreaterThan(0);
    expect(await osvAffectsCount(pool, PKG2)).toBe(await osvAffectsCount(pool, PKG));
  });

  it("removes an advisory omitted from a later package response", async () => {
    await osvSyncAll(pool);
    expect(await osvAffectsForCve(pool, PKG, BOTH)).toBeGreaterThan(0);

    server.use(
      http.post("https://api.osv.dev/v1/query", () =>
        HttpResponse.json({ vulns: osvFixture.vulns.filter((v) => cveId(v) !== BOTH) }),
      ),
    );
    await osvSyncAll(pool);

    expect(await osvAffectsForCve(pool, PKG, BOTH)).toBe(0);
    expect(await osvAffectsCount(pool, PKG)).toBeGreaterThan(0);
  });
});

function cveId(vuln: OsvVuln): string | undefined {
  return vuln.id.match(/^CVE-/)
    ? vuln.id
    : vuln.aliases?.find((alias) => /^CVE-\d{4}-\d+$/.test(alias));
}

async function osvAffectsCount(pool: Pool, pkg: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1 AND source = 'osv'`,
    [pkg],
  );
  return rows[0].n;
}

async function osvAffectsForCve(pool: Pool, pkg: string, cveId: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM cve_affects
     WHERE package_name = $1 AND source = 'osv' AND cve_id = $2`,
    [pkg, cveId],
  );
  return rows[0].n;
}
