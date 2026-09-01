import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  upsertCveFull,
  upsertCveStub,
  deleteAffectsForSource,
  insertAffects,
  flagKev,
  clearKevExcept,
  knownCveIds,
  getCveById,
  listAffectsWithCveForPackage,
  listAffectedPackagesForCve,
  AffectsInsert,
} from "../../src/db/queries/cves.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-cves-pkg";
const PKG2 = "test-cves-pkg2";
const CVE = "CVE-2099-0001";
const CVE2 = "CVE-2099-0002";

function affects(overrides: Partial<AffectsInsert>): AffectsInsert {
  return {
    cve_id: CVE,
    package_name: PKG,
    version_start: null,
    version_start_excl: false,
    version_end: "2.0.0",
    version_end_excl: true,
    exact_version: null,
    fixed_in: "2.0.0",
    source: "nvd",
    raw_cpe: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
    version_na: false,
    ...overrides,
  };
}

describe("cves queries", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    for (const name of [PKG, PKG2]) {
      await upsertPackage(pool, {
        name,
        display_name: name,
        vendor: "Acme",
        description: null,
        website: null,
        config_hash: "h",
        enabled: true,
      });
    }
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [[CVE, CVE2]]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG2]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [[CVE, CVE2]]);
  });

  it("upserts a full CVE and reads it back", async () => {
    await upsertCveFull(pool, {
      id: CVE,
      published_at: "2099-01-01T00:00:00Z",
      modified_at: "2099-02-01T00:00:00Z",
      cvss_v3_score: 9.8,
      cvss_v3_vector: "AV:N",
      severity: "CRITICAL",
      description: "boom",
      raw: { cve: { id: CVE } },
    });
    const row = await getCveById(pool, CVE);
    expect(row).not.toBeNull();
    expect(row!.severity).toBe("CRITICAL");
    expect(Number(row!.cvss_v3_score)).toBe(9.8);
    expect(row!.is_kev).toBe(false);
  });

  it("full upsert overwrites, stub upsert does not clobber existing rows", async () => {
    await upsertCveFull(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: 7.5,
      cvss_v3_vector: null,
      severity: "HIGH",
      description: "full",
      raw: { cve: { id: CVE } },
    });
    const created = await upsertCveStub(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      description: "stub should not win",
      raw: { osvStub: true },
    });
    expect(created).toBe(0); // already existed
    const row = await getCveById(pool, CVE);
    expect(row!.description).toBe("full");
    expect(row!.severity).toBe("HIGH");
  });

  it("stub insert reports 1 for a genuinely new CVE", async () => {
    const created = await upsertCveStub(pool, {
      id: CVE2,
      published_at: null,
      modified_at: null,
      description: "osv only",
      raw: { osvStub: true },
    });
    expect(created).toBe(1);
  });

  it("dedupes affects rows on (cve, package, source, raw_cpe) including null raw_cpe", async () => {
    await upsertCveFull(pool, blankCve(CVE));
    const row = affects({ raw_cpe: null, source: "osv" });
    const a = await insertAffects(pool, row);
    const b = await insertAffects(pool, row); // identical, incl. null raw_cpe
    expect(a).toBe(1);
    expect(b).toBe(0);
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM cve_affects WHERE cve_id = $1`,
      [CVE],
    );
    expect(rows[0].n).toBe(1);
  });

  it("rebuilds only same-source affects rows, leaving other sources intact", async () => {
    await upsertCveFull(pool, blankCve(CVE));
    await insertAffects(pool, affects({ source: "nvd", raw_cpe: "nvd-a" }));
    await insertAffects(pool, affects({ source: "osv", raw_cpe: null }));

    await deleteAffectsForSource(pool, CVE, "nvd");
    const { rows } = await pool.query<{ source: string }>(
      `SELECT source FROM cve_affects WHERE cve_id = $1`,
      [CVE],
    );
    expect(rows.map((r) => r.source)).toEqual(["osv"]);
  });

  it("flags and clears KEV", async () => {
    await upsertCveFull(pool, blankCve(CVE));
    await upsertCveFull(pool, blankCve(CVE2));
    const known = await knownCveIds(pool, [CVE, CVE2, "CVE-0000-0000"]);
    expect(known.has(CVE)).toBe(true);
    expect(known.has("CVE-0000-0000")).toBe(false);

    await flagKev(pool, CVE, "2099-03-01");
    let row = await getCveById(pool, CVE);
    expect(row!.is_kev).toBe(true);

    // Clear KEV on everything not in the (now empty of CVE) set → CVE gets cleared.
    const cleared = await clearKevExcept(pool, [CVE2]);
    expect(cleared).toBeGreaterThanOrEqual(1);
    row = await getCveById(pool, CVE);
    expect(row!.is_kev).toBe(false);
  });

  it("joins affects with cve metadata for a package, and affected packages for a cve", async () => {
    await upsertCveFull(pool, {
      ...blankCve(CVE),
      severity: "HIGH",
      description: "shared cve",
    });
    await insertAffects(pool, affects({ package_name: PKG, raw_cpe: "a" }));
    await insertAffects(pool, affects({ package_name: PKG2, raw_cpe: "b" }));

    const forPkg = await listAffectsWithCveForPackage(pool, PKG);
    expect(forPkg).toHaveLength(1);
    expect(forPkg[0].severity).toBe("HIGH");
    expect(forPkg[0].cve_id).toBe(CVE);

    const forCve = await listAffectedPackagesForCve(pool, CVE);
    expect(forCve.map((r) => r.package_name).sort()).toEqual([PKG, PKG2]);
  });

  // WAL-104. The loader is package-scoped and unbounded, and seven call sites reach it —
  // `download.ts` among them — so anything it selects per row is paid for on the serving path,
  // once per download, for the whole of a package's CVE history. Selecting `c.raw` whole meant
  // parsing every advisory a JDK had ever had into a 384 MiB heap before a byte went out, and it
  // aborted `walrus-api` sixteen times on GCP before anyone noticed.
  //
  // Mutation check: restore `c.raw` in place of the CASE expression in
  // `listAffectsWithCveForPackage` and the projection test below fails on both of its
  // assertions — the advisory body comes back, and `configurations` reappears beside
  // `references`. The other two tests pass either way by design: they do not guard the
  // projection, they guard the two ways the projection itself can go wrong. The null one is
  // not hypothetical — the first version of this fix used `c.raw IS NULL`, which is never true
  // on a `JSONB NOT NULL` column, and turned every advisory-less CVE's `raw` from `null` into
  // an object. That test is the only reason it did not ship.
  it("projects only the reference URLs out of the advisory, never the whole thing (WAL-104)", async () => {
    await upsertCveFull(pool, {
      ...blankCve(CVE),
      raw: {
        cve: {
          id: CVE,
          references: [{ url: "https://example.test/advisory" }],
          // The parts that make a real NVD advisory large. None of them is read by anything,
          // and all of them used to travel to every caller on every request.
          descriptions: [{ lang: "en", value: "x".repeat(4096) }],
          configurations: Array.from({ length: 64 }, (_, i) => ({
            nodes: [{ cpeMatch: [{ criteria: `cpe:2.3:a:acme:widget:${i}:*:*:*:*:*:*:*` }] }],
          })),
        },
      },
    });
    await insertAffects(pool, affects({}));

    const [row] = await listAffectsWithCveForPackage(pool, PKG);
    expect(row.raw).toEqual({ cve: { references: [{ url: "https://example.test/advisory" }] } });
    expect(Object.keys(row.raw?.cve ?? {})).toEqual(["references"]);
  });

  it("keeps a null advisory null rather than inventing an empty one (WAL-104)", async () => {
    await upsertCveFull(pool, { ...blankCve(CVE), raw: null });
    await insertAffects(pool, affects({}));

    const [row] = await listAffectsWithCveForPackage(pool, PKG);
    expect(row.raw).toBeNull();
  });

  it("still reaches the references a CVE genuinely has, so /vulns keeps its links (WAL-104)", async () => {
    await upsertCveFull(pool, {
      ...blankCve(CVE),
      raw: { cve: { id: CVE, references: [{ url: "https://a.test" }, { url: "https://b.test" }] } },
    });
    await insertAffects(pool, affects({}));

    const [row] = await listAffectsWithCveForPackage(pool, PKG);
    expect(row.raw?.cve?.references?.map((r) => r.url)).toEqual([
      "https://a.test",
      "https://b.test",
    ]);
  });

  it("carries the CPE version-NA flag through insert and select (WAL-69)", async () => {
    await upsertCveFull(pool, blankCve(CVE));
    await insertAffects(
      pool,
      affects({
        version_na: true,
        version_start: null,
        version_end: null,
        fixed_in: null,
        raw_cpe: "cpe:2.3:a:microsoft:visual_studio_code:-:*:*:*:*:*:*:*",
      }),
    );

    const rows = await listAffectsWithCveForPackage(pool, PKG);
    expect(rows).toHaveLength(1);
    expect(rows[0].version_na).toBe(true);
  });

  it("defaults version_na to false when the caller omits it", async () => {
    await upsertCveFull(pool, blankCve(CVE));
    const row = affects({ raw_cpe: "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*" });
    delete (row as Partial<AffectsInsert>).version_na;

    await insertAffects(pool, row);

    const rows = await listAffectsWithCveForPackage(pool, PKG);
    expect(rows[0].version_na).toBe(false);
  });

  it("cascades affects deletion when a package is deleted", async () => {
    const tmp = "test-cves-cascade";
    await upsertPackage(pool, {
      name: tmp,
      display_name: tmp,
      vendor: "Acme",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await upsertCveFull(pool, blankCve(CVE));
    await insertAffects(pool, affects({ package_name: tmp, raw_cpe: "x" }));
    await pool.query(`DELETE FROM packages WHERE name = $1`, [tmp]);
    const { rows } = await pool.query(
      `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1`,
      [tmp],
    );
    expect(rows[0].n).toBe(0);
  });
});

function blankCve(id: string) {
  return {
    id,
    published_at: null,
    modified_at: null,
    cvss_v3_score: null,
    cvss_v3_vector: null,
    severity: null,
    description: null,
    raw: { cve: { id } },
  };
}
