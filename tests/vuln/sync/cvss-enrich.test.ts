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

/** An NVD client whose CVE is scored ONLY under CVSS v4.0 (Deferred-backlog shape). */
function nvdReturningV4Only(score: number, severity = "CRITICAL"): NvdClient {
  return {
    cveById: async (id: string) =>
      id !== CVE
        ? null
        : {
            cve: {
              id: CVE,
              metrics: {
                cvssMetricV40: [
                  {
                    cvssData: {
                      baseScore: score,
                      vectorString: "CVSS:4.0/AV:N",
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
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'cvss'`);
    await pool.query(`DELETE FROM cves WHERE id LIKE $1`, [`${CVE}%`]);
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

  // WAL-50: the one scheduled trigger that can newly block downloads must be visible to
  // /app/status and staleness degradations, like nvd/kev/osv are. A dry run must write nothing.
  it("records sync-state for a real run, leaves nothing for a dry run", async () => {
    await seedCandidate();

    const stateBefore = async () =>
      (await pool.query(`SELECT last_ok FROM vuln_sync_state WHERE source = 'cvss'`)).rows;

    await enrichMissingCvss(pool, nvdReturning(9.6), { dryRun: true });
    expect(await stateBefore()).toEqual([]); // dry run writes nothing anywhere

    await enrichMissingCvss(pool, nvdReturning(9.6));
    const { rows } = await pool.query(
      `SELECT last_ok, last_success_at IS NOT NULL AS has_success
       FROM vuln_sync_state WHERE source = 'cvss'`,
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].last_ok).toBe(true); // walk completed — errors stay candidates either way
    expect(rows[0].has_success).toBe(true);
  });

  it("counts total fetch failure as a completed run, leaving candidates for next time", async () => {
    // Per-CVE fetch errors are swallowed by design (a transient outage must not strand
    // the backlog or burn a sentinel); the run itself completes and reports ok.
    await seedCandidate();
    await upsertCveFull(pool, {
      id: `${CVE}-B`,
      published_at: null,
      modified_at: null,
      cvss_v3_score: null,
      cvss_v3_vector: null,
      severity: null,
      description: null,
      raw: { cve: { id: `${CVE}-B` } },
    });

    const nvdErroring = {
      cveById: async () => {
        throw new Error("NVD unreachable");
      },
    } as unknown as NvdClient;
    const result = await enrichMissingCvss(pool, nvdErroring);
    expect(result.errors).toBe(2);
    expect(result.updated).toBe(0);

    const { rows } = await pool.query(`SELECT last_ok FROM vuln_sync_state WHERE source = 'cvss'`);
    expect(rows[0].last_ok).toBe(true);

    const { rows: candidates } = await pool.query(
      `SELECT count(*)::int AS n FROM cves WHERE severity IS NULL AND severity_source IS NULL
       AND id IN ($1, $2)`,
      [CVE, `${CVE}-B`],
    );
    expect(candidates[0].n).toBe(2); // stayed candidates — no sentinel on transient errors
  });

  // Before v4 support, this CVE was recorded as no_metrics — a terminal sentinel —
  // and a version affected by a v4-only 9.5 kept serving forever.
  it("scores a v4-only CVE, crosses the gate, and blocks the cached version", async () => {
    await seedCandidate();

    const preview = await enrichMissingCvss(pool, nvdReturningV4Only(9.5), { dryRun: true });
    expect(preview.no_metrics).toBe(0);
    const proposal = preview.proposals.find((p) => p.cve_id === CVE);
    expect(proposal).toMatchObject({
      severity: "CRITICAL",
      severity_source: "nvd-cvss-v4",
      cvss_v3_score: null,
      cvss_v4_score: 9.5,
      crosses_critical_gate: true,
    });
    const deltas = await previewGateDelta(pool, preview.proposals);
    expect(deltas.find((d) => d.package_name === PKG)?.newly_blocked).toContain(VERSION);

    const result = await enrichMissingCvss(pool, nvdReturningV4Only(9.5));
    expect(result.updated).toBe(1);
    const { rows } = await pool.query(
      `SELECT severity, severity_source, cvss_v3_score, cvss_v4_score, cvss_v4_vector
       FROM cves WHERE id = $1`,
      [CVE],
    );
    expect(rows[0].severity).toBe("CRITICAL");
    expect(rows[0].severity_source).toBe("nvd-cvss-v4");
    expect(rows[0].cvss_v3_score).toBeNull();
    expect(Number(rows[0].cvss_v4_score)).toBe(9.5);
    expect(rows[0].cvss_v4_vector).toBe("CVSS:4.0/AV:N");
  });

  it("proposes a sub-threshold v4-only score without crossing the gate", async () => {
    await seedCandidate();

    const preview = await enrichMissingCvss(pool, nvdReturningV4Only(6.9, "MEDIUM"), {
      dryRun: true,
    });
    const proposal = preview.proposals.find((p) => p.cve_id === CVE);
    expect(proposal).toMatchObject({
      severity: "MEDIUM",
      severity_source: "nvd-cvss-v4",
      cvss_v4_score: 6.9,
      crosses_critical_gate: false,
    });
  });
});
