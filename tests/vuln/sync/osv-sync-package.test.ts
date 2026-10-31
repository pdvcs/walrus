import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { readFileSync } from "fs";
import { join } from "path";
import { Pool } from "pg";
import { runMigrations } from "../../../src/db/client.js";
import { getPackage, upsertPackage } from "../../../src/db/queries/packages.js";
import { reconcilePackageVuln } from "../../../src/db/queries/package-aliases.js";
import { getSyncCursor } from "../../../src/db/queries/vuln-sync-state.js";
import { osvSyncAll, osvSyncPackage, type OsvVuln } from "../../../src/vuln/sync/osv-sync.js";
import {
  createVulnBackfillJob,
  getVulnBackfillJob,
} from "../../../src/db/queries/vuln-backfill-jobs.js";
import { runVulnBackfillJob } from "../../../src/services/vuln-backfill.js";
import type { NvdClient } from "../../../src/vuln/sync/nvd-client.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const osvFixture = JSON.parse(
  readFileSync(join(process.cwd(), "tests/fixtures/vuln/osv-go-stdlib.json"), "utf8"),
) as { vulns: OsvVuln[] };
const osvCveIds = osvFixture.vulns
  .map((v) => (v.id.match(/^CVE-/) ? v.id : v.aliases?.find((a) => /^CVE-\d{4}-\d+$/.test(a))))
  .filter((x): x is string => Boolean(x));

const MAPPED = "test-osvpkg-mapped";
const OTHER = "test-osvpkg-other";
const UNMAPPED = "test-osvpkg-unmapped";
const NAMES = [MAPPED, OTHER, UNMAPPED];

// WAL-54: a targeted OSV sync, so a newly tracked package is complete after its own backfill
// rather than a week later, and an `osv_synced_at` marker so "no advisories" can be told apart
// from "never looked".
describe("osvSyncPackage", () => {
  let pool: Pool;
  const server = setupServer();

  async function seed(name: string, mapped: boolean) {
    await upsertPackage(pool, {
      name,
      display_name: name,
      vendor: "T",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: name,
      aliases: [name],
      cpes: [{ cpe_vendor: "acme", cpe_product: name, is_primary: true }],
      osvEcosystem: mapped ? "Go" : null,
      osvName: mapped ? "stdlib" : null,
    });
  }

  async function cleanup() {
    await pool.query(`DELETE FROM cves WHERE id = ANY($1)`, [osvCveIds]);
    await pool.query(`DELETE FROM package_cpes WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM package_aliases WHERE package_name = ANY($1)`, [NAMES]);
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [NAMES]);
  }

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
    server.listen({ onUnhandledRequest: "error" });
  });

  afterAll(async () => {
    server.close();
    await cleanup();
    await pool.end();
  });

  beforeEach(async () => {
    server.resetHandlers();
    await cleanup();
    await pool.query(`DELETE FROM vuln_sync_state WHERE source = 'osv'`);
    await seed(MAPPED, true);
    await seed(OTHER, true);
    await seed(UNMAPPED, false);
    server.use(
      http.post("https://api.osv.dev/v1/query", () =>
        HttpResponse.json({ vulns: osvFixture.vulns }),
      ),
    );
  });

  async function osvRows(name: string): Promise<number> {
    const r = await pool.query(
      `SELECT count(*)::int AS n FROM cve_affects WHERE package_name = $1 AND source = 'osv'`,
      [name],
    );
    return r.rows[0].n;
  }

  it("syncs only the named package and records that OSV was read", async () => {
    expect((await getPackage(pool, MAPPED))!.osv_synced_at).toBeNull();

    const result = await osvSyncPackage(pool, MAPPED);

    expect(result!.affectsUpserted).toBeGreaterThan(0);
    expect(await osvRows(MAPPED)).toBeGreaterThan(0);
    expect(await osvRows(OTHER)).toBe(0); // a targeted run must not touch other packages
    expect((await getPackage(pool, MAPPED))!.osv_synced_at).not.toBeNull();
    expect((await getPackage(pool, OTHER))!.osv_synced_at).toBeNull();
  });

  it("leaves the global OSV sync state alone", async () => {
    await osvSyncPackage(pool, MAPPED);
    // One package succeeding says nothing about whether the whole cross-check is fresh.
    expect(await getSyncCursor(pool, "osv")).toBeNull();
  });

  it("returns null and marks nothing for a package with no OSV mapping", async () => {
    expect(await osvSyncPackage(pool, UNMAPPED)).toBeNull();
    expect((await getPackage(pool, UNMAPPED))!.osv_synced_at).toBeNull();
  });

  it("marks a package synced even when OSV returns no advisories", async () => {
    server.use(http.post("https://api.osv.dev/v1/query", () => HttpResponse.json({})));
    const result = await osvSyncPackage(pool, MAPPED);
    expect(result!.vulns).toBe(0);
    // Looked and found nothing is a different fact from never having looked.
    expect((await getPackage(pool, MAPPED))!.osv_synced_at).not.toBeNull();
  });

  it("does not mark a package whose OSV query failed", async () => {
    server.use(
      http.post("https://api.osv.dev/v1/query", () => new HttpResponse(null, { status: 500 })),
    );
    await expect(osvSyncPackage(pool, MAPPED)).rejects.toThrow();
    expect((await getPackage(pool, MAPPED))!.osv_synced_at).toBeNull();
  });

  it("the full sync marks every package it read", async () => {
    await osvSyncAll(pool);
    expect((await getPackage(pool, MAPPED))!.osv_synced_at).not.toBeNull();
    expect((await getPackage(pool, OTHER))!.osv_synced_at).not.toBeNull();
    expect((await getPackage(pool, UNMAPPED))!.osv_synced_at).toBeNull();
  });

  describe("in a targeted backfill job", () => {
    const nvd = { cvePages: vi.fn(async function* () {}) } as unknown as NvdClient;
    const osvOk = () =>
      vi.fn(async () => new Response(JSON.stringify({ vulns: osvFixture.vulns }), { status: 200 }));

    it("also reads OSV for the package, so a new entry is complete after its own backfill", async () => {
      const job = await createVulnBackfillJob(pool, undefined, MAPPED);
      await runVulnBackfillJob(pool, job.id, nvd, osvOk() as unknown as typeof fetch);

      expect((await getVulnBackfillJob(pool, job.id))?.status).toBe("succeeded");
      expect(await osvRows(MAPPED)).toBeGreaterThan(0);
      expect((await getPackage(pool, MAPPED))!.osv_synced_at).not.toBeNull();
      expect((await getPackage(pool, OTHER))!.osv_synced_at).toBeNull();
    });

    it("does not fail the NVD backfill when OSV is down, and leaves the package unmarked", async () => {
      const down = vi.fn(async () => new Response("nope", { status: 500 }));
      const job = await createVulnBackfillJob(pool, undefined, MAPPED);
      await runVulnBackfillJob(pool, job.id, nvd, down as unknown as typeof fetch);

      expect((await getVulnBackfillJob(pool, job.id))?.status).toBe("succeeded");
      // Not covered: posture must keep reporting unknown rather than claim OSV was read.
      expect((await getPackage(pool, MAPPED))!.osv_synced_at).toBeNull();
    });

    it("skips OSV for a whole-fleet backfill (no package scope)", async () => {
      const osv = osvOk();
      const job = await createVulnBackfillJob(pool);
      await runVulnBackfillJob(pool, job.id, nvd, osv as unknown as typeof fetch);
      expect(osv).not.toHaveBeenCalled();
    });
  });
});
