import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
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
import { osvSyncAll, type OsvVuln } from "../../../src/vuln/sync/osv-sync.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const osvFixture = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vuln/osv-go-stdlib.json"), "utf8"),
) as { vulns: OsvVuln[] };
const osvCveIds = osvFixture.vulns
  .map((v) => (v.id.match(/^CVE-/) ? v.id : v.aliases?.find((a) => /^CVE-\d{4}-\d+$/.test(a))))
  .filter((x): x is string => Boolean(x));

const PKG = "test-go-osv";
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
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await pool.end();
  });

  beforeEach(async () => {
    server.resetHandlers();
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [osvCveIds]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
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
});

async function osvAffectsCount(pool: Pool, pkg: string): Promise<number> {
  const { rows } = await pool.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1 AND source = 'osv'`,
    [pkg],
  );
  return rows[0].n;
}
