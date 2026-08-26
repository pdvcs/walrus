import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../../src/db/client.js";
import { upsertPackage } from "../../../src/db/queries/packages.js";
import { insertVersion } from "../../../src/db/queries/versions.js";
import { upsertCveFull, insertAffects } from "../../../src/db/queries/cves.js";
import type { NvdClient } from "../../../src/vuln/sync/nvd-client.js";
import { enrichMissingCvss, previewGateDelta } from "../../../src/vuln/sync/cvss-enrich.js";

/**
 * `cvss-enrich.ts` had no test at all, despite being the module that can turn a served
 * version into a 403 — enrichment can newly satisfy the >= 9.0 download gate.
 */
const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const PKG = "res-enrich-pkg";
const CVE = "CVE-2099-7200";
const VERSION = "2.0.0";

/** An NVD client that answers for CVE alone, with the score the test wants. */
function nvdReturning(score: number | null, severity = "CRITICAL"): NvdClient {
  return {
    cveById: async (id: string) =>
      id !== CVE
        ? null
        : {
            cve: {
              id: CVE,
              metrics: {
                cvssMetricV31: [
                  {
                    cvssData: {
                      baseScore: score,
                      vectorString: "CVSS:3.1/AV:N",
                      baseSeverity: severity,
                    },
                  },
                ],
              },
            },
          },
  } as unknown as NvdClient;
}

describe("cvss enrichment", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  async function cleanup() {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM version_availability_events WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
  }

  afterAll(async () => {
    await cleanup();
    await pool.end();
  });

  beforeEach(cleanup);

  /** A severity-less CVE affecting a cached version — the enrichment candidate. */
  async function seedCandidate() {
    await upsertPackage(pool, {
      name: PKG,
      display_name: PKG,
      vendor: "T",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await insertVersion(pool, {
      package_name: PKG,
      version: VERSION,
      version_group: "2.0",
      is_lts: false,
      version_sort: "0002.0000.0000",
    });
    await upsertCveFull(pool, {
      id: CVE,
      published_at: null,
      modified_at: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      severity: null,
      description: null,
      raw: { cve: { id: CVE } },
    });
    await insertAffects(pool, {
      cve_id: CVE,
      package_name: PKG,
      version_start: null,
      version_start_excl: false,
      version_end: null,
      version_end_excl: false,
      exact_version: VERSION,
      fixed_in: null,
      source: "osv",
      raw_cpe: `cpe:2.3:a:t:t:${VERSION}`,
    });
  }

  it("reports a CVE crossing 9.0 as blocking a known cached version", async () => {
    await seedCandidate();

    const result = await enrichMissingCvss(pool, nvdReturning(9.6), { dryRun: true });
    const proposal = result.proposals.find((p) => p.cve_id === CVE);

    expect(proposal).toBeDefined();
    expect(proposal!.crosses_critical_gate).toBe(true);

    const deltas = await previewGateDelta(pool, result.proposals);
    expect(deltas.find((d) => d.package_name === PKG)?.newly_blocked).toContain(VERSION);
  });

  it("reports no gate change for a CVE scored below the threshold", async () => {
    await seedCandidate();

    const result = await enrichMissingCvss(pool, nvdReturning(5.0, "MEDIUM"), { dryRun: true });
    const proposal = result.proposals.find((p) => p.cve_id === CVE);

    expect(proposal!.crosses_critical_gate).toBe(false);
    const deltas = await previewGateDelta(pool, result.proposals);
    expect(deltas.find((d) => d.package_name === PKG)).toBeUndefined();
  });

  it("computes the delta against pre-write state, and a dry run writes nothing", async () => {
    await seedCandidate();

    const result = await enrichMissingCvss(pool, nvdReturning(9.6), { dryRun: true });
    expect(result.updated).toBe(0);

    const { rows } = await pool.query(`SELECT severity, cvss_v3_score FROM cves WHERE id = $1`, [
      CVE,
    ]);
    expect(rows[0].severity).toBeNull();
    expect(rows[0].cvss_v3_score).toBeNull();

    // previewGateDelta diffs current rows against the same rows with proposals patched in,
    // so run *after* applying it would report nothing — the patch would already be reality.
    const deltas = await previewGateDelta(pool, result.proposals);
    expect(deltas.find((d) => d.package_name === PKG)?.newly_blocked).toContain(VERSION);
  });

  it("applies the score when not a dry run", async () => {
    await seedCandidate();

    const result = await enrichMissingCvss(pool, nvdReturning(9.6));
    expect(result.updated).toBe(1);

    const { rows } = await pool.query(`SELECT severity, cvss_v3_score FROM cves WHERE id = $1`, [
      CVE,
    ]);
    expect(rows[0].severity).toBe("CRITICAL");
    expect(Number(rows[0].cvss_v3_score)).toBe(9.6);
  });
});
