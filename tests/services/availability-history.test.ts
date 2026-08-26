import { describe, expect, it, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { insertVersion } from "../../src/db/queries/versions.js";
import { upsertCveFull, insertAffects } from "../../src/db/queries/cves.js";
import {
  listAvailabilityHistory,
  recordAvailabilityTransitions,
} from "../../src/services/availability-history.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const PKG = "res-avail-pkg";
const CVE = "CVE-2099-7100";

async function seedPackageWithVersion(pool: Pool, version: string) {
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
    version,
    version_group: "1.0",
    is_lts: false,
    version_sort: "0001.0000.0000",
  });
}

/** Make CVE critical enough to trip the >= 9.0 gate for `version`. */
async function addCriticalCve(
  pool: Pool,
  version: string,
  score: string,
  extra: Partial<{
    cvss_v3_score: string | null;
    cvss_v4_score: string;
    cvss_v2_score: string;
    severity: string;
    severity_source: string;
  }> = {},
) {
  await upsertCveFull(pool, {
    id: CVE,
    published_at: null,
    modified_at: null,
    cvss_v3_score: extra.cvss_v3_score ?? score,
    cvss_v3_vector: null,
    cvss_v4_score: extra.cvss_v4_score ?? null,
    cvss_v4_vector: null,
    cvss_v2_score: extra.cvss_v2_score ?? null,
    cvss_v2_vector: null,
    severity: extra.severity ?? "CRITICAL",
    severity_source: extra.severity_source ?? "nvd-cvss-v3",
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
    exact_version: version,
    fixed_in: null,
    source: "nvd",
    raw_cpe: `cpe:2.3:a:t:t:${version}`,
  });
}

describe("version availability history", () => {
  let pool: Pool;
  const version = "1.0.0";

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  // `versions` has no ON DELETE CASCADE from `packages`, so order matters here.
  async function cleanup() {
    await pool.query(`DELETE FROM cves WHERE id = $1`, [CVE]);
    await pool.query(`DELETE FROM version_availability_events WHERE package_name = $1`, [PKG]);
    await pool.query(
      `DELETE FROM artifacts WHERE version_id IN
                        (SELECT id FROM versions WHERE package_name = $1)`,
      [PKG],
    );
    await pool.query(`DELETE FROM versions WHERE package_name = $1`, [PKG]);
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
  }

  afterAll(async () => {
    await cleanup();
    await pool.end();
  });

  beforeEach(cleanup);

  it("records nothing for a version that was and stays available", async () => {
    // Writing an "available" row for every untouched version on every run would bury the
    // transitions that matter under thousands that say nothing happened.
    await seedPackageWithVersion(pool, version);
    await recordAvailabilityTransitions(pool, { source: "nvd", trigger: "internal" });

    expect(await listAvailabilityHistory(pool, PKG, version)).toEqual([]);
  });

  it("records when a version became blocked, and which CVE did it", async () => {
    await seedPackageWithVersion(pool, version);
    await addCriticalCve(pool, version, "9.6");

    await recordAvailabilityTransitions(pool, { source: "cvss", trigger: "internal" });

    const history = await listAvailabilityHistory(pool, PKG, version);
    expect(history).toHaveLength(1);
    expect(history[0].status).toBe("blocked");
    expect(history[0].cve_id).toBe(CVE);
    expect(Number(history[0].cvss_v3_score)).toBe(9.6);
    expect(history[0].severity_source).toBe("nvd-cvss-v3");
    expect(history[0].source).toBe("cvss");
    expect(history[0].trigger_type).toBe("internal");
  });

  // Review walrus-0826-review-02.md §3.1: the gate is any-of across score versions, so a
  // CVE whose v3 (8.1/HIGH) is sub-threshold but whose v4 is 9.1 blocks legitimately — and
  // before the provenance columns the event showed only "8.1/HIGH blocked", evidence that
  // contradicted the policy it enforced. Live example: CVE-2026-6100 on python.
  it("explains a v4-caused block: all scores recorded plus which one produced severity", async () => {
    await seedPackageWithVersion(pool, version);
    await addCriticalCve(pool, version, "8.1", {
      cvss_v4_score: "9.1",
      severity: "HIGH",
      severity_source: "nvd-cvss-v4",
    });

    await recordAvailabilityTransitions(pool, { source: "nvd", trigger: "internal" });

    const history = await listAvailabilityHistory(pool, PKG, version);
    expect(history).toHaveLength(1);
    expect(history[0].status).toBe("blocked");
    expect(Number(history[0].cvss_v3_score)).toBe(8.1); // stored as-is — the truth about v3
    expect(Number(history[0].cvss_v4_score)).toBe(9.1); // …and the number that blocked
    expect(history[0].cvss_v2_score).toBeNull();
    expect(history[0].severity).toBe("HIGH");
    expect(history[0].severity_source).toBe("nvd-cvss-v4"); // pointing at the tripped score
  });

  it("does not re-record a version that was already blocked", async () => {
    await seedPackageWithVersion(pool, version);
    await addCriticalCve(pool, version, "9.6");

    await recordAvailabilityTransitions(pool, { source: "nvd", trigger: "internal" });
    await recordAvailabilityTransitions(pool, { source: "nvd", trigger: "internal" });

    // Rows are transitions, not observations: two-hourly ingestion must not append a row
    // per run for a version whose status has not moved.
    expect(await listAvailabilityHistory(pool, PKG, version)).toHaveLength(1);
  });

  it("retains both transitions, in order, when a version is unblocked again", async () => {
    await seedPackageWithVersion(pool, version);
    await addCriticalCve(pool, version, "9.6");
    await recordAvailabilityTransitions(pool, { source: "nvd", trigger: "internal" });

    // The CVE is rescored below the gate — the version becomes servable again.
    await pool.query(`UPDATE cves SET cvss_v3_score = 5.0, severity = 'MEDIUM' WHERE id = $1`, [
      CVE,
    ]);
    await recordAvailabilityTransitions(pool, { source: "cvss", trigger: "admin" });

    const history = await listAvailabilityHistory(pool, PKG, version);
    expect(history.map((h) => h.status)).toEqual(["available", "blocked"]); // newest first
    expect(history[0].cve_id).toBeNull(); // nothing "causes" availability
    expect(history[0].trigger_type).toBe("admin");
  });

  it("attributes a transition to whichever source caused it, not just cvss", async () => {
    await seedPackageWithVersion(pool, version);
    await addCriticalCve(pool, version, "9.8");

    await recordAvailabilityTransitions(pool, { source: "backfill", trigger: "internal" });

    const history = await listAvailabilityHistory(pool, PKG, version);
    expect(history[0].source).toBe("backfill");
  });
});
