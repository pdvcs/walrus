import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import { reconcilePackageVuln } from "../../src/db/queries/package-aliases.js";
import {
  createVulnBackfillJob,
  getVulnBackfillJob,
} from "../../src/db/queries/vuln-backfill-jobs.js";
import { runVulnBackfillJob } from "../../src/services/vuln-backfill.js";
import type { NvdClient } from "../../src/vuln/sync/nvd-client.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";

const PKG = "test-backfill-scoped";
const PKG_TWO_PAIRS = "test-backfill-twopair";

describe("targeted vuln backfill jobs", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = ANY($1)`, [[PKG, PKG_TWO_PAIRS]]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM vuln_backfill_jobs`);
    await seed(PKG, [{ cpe_vendor: "acme", cpe_product: "widget", is_primary: true }]);
    await seed(PKG_TWO_PAIRS, [
      { cpe_vendor: "acme", cpe_product: "gadget", is_primary: true },
      { cpe_vendor: "acme", cpe_product: "doohickey", is_primary: false },
    ]);
  });

  async function seed(
    name: string,
    cpes: Array<{ cpe_vendor: string; cpe_product: string; is_primary: boolean }>,
  ): Promise<void> {
    await upsertPackage(pool, {
      name,
      display_name: name,
      vendor: "v",
      description: null,
      website: null,
      config_hash: "h",
      enabled: true,
    });
    await reconcilePackageVuln(pool, {
      packageName: name,
      aliases: [name],
      cpes,
      osvEcosystem: null,
      osvName: null,
    });
  }

  it("defaults package_name to null (full backfill)", async () => {
    const job = await createVulnBackfillJob(pool);
    expect(job.package_name).toBeNull();
  });

  it("persists the package scope on the job row", async () => {
    const job = await createVulnBackfillJob(pool, undefined, PKG);
    expect(job.package_name).toBe(PKG);
    expect((await getVulnBackfillJob(pool, job.id))?.package_name).toBe(PKG);
  });

  it("walks only the scoped package's pairs and reports a scoped cpe_pairs_total", async () => {
    // backfillNvd pages rather than accumulating (WAL-97), so the seam is cvePages: an async
    // generator that yields nothing stands in for a CPE pair with no matching CVEs.
    const cvePages = vi.fn(async function* () {});
    const job = await createVulnBackfillJob(pool, undefined, PKG_TWO_PAIRS);

    await runVulnBackfillJob(pool, job.id, { cvePages } as unknown as NvdClient);

    const matchStrings = cvePages.mock.calls
      .map((c) => (c[0] as { virtualMatchString: string }).virtualMatchString)
      .sort();
    expect(matchStrings).toEqual(["cpe:2.3:a:acme:doohickey", "cpe:2.3:a:acme:gadget"]);

    const finished = await getVulnBackfillJob(pool, job.id);
    expect(finished?.status).toBe("succeeded");
    expect(finished?.cpe_pairs_total).toBe(2);
    expect(finished?.cpe_pairs_done).toBe(2);
  });

  it("records failure without losing the package scope", async () => {
    // An async iterable whose first `next()` rejects — an upstream failure on the first page.
    // Written out rather than as a generator, which would need an unreachable `yield` to satisfy
    // require-yield.
    const nvd = {
      cvePages: vi.fn(() => ({
        [Symbol.asyncIterator]: () => ({
          next: () => Promise.reject(new Error("upstream boom")),
        }),
      })),
    } as unknown as NvdClient;
    const job = await createVulnBackfillJob(pool, undefined, PKG);

    await expect(runVulnBackfillJob(pool, job.id, nvd)).rejects.toThrow("boom");

    const failed = await getVulnBackfillJob(pool, job.id);
    expect(failed?.status).toBe("failed");
    expect(failed?.package_name).toBe(PKG);
    expect(failed?.error_message).toMatch(/boom/);
  });
});
