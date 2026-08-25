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
    const cvesForCpe = vi.fn().mockResolvedValue([]);
    const job = await createVulnBackfillJob(pool, undefined, PKG_TWO_PAIRS);

    await runVulnBackfillJob(pool, job.id, { cvesForCpe } as unknown as NvdClient);

    const matchStrings = cvesForCpe.mock.calls.map((c) => c[0] as string).sort();
    expect(matchStrings).toEqual(["cpe:2.3:a:acme:doohickey", "cpe:2.3:a:acme:gadget"]);

    const finished = await getVulnBackfillJob(pool, job.id);
    expect(finished?.status).toBe("succeeded");
    expect(finished?.cpe_pairs_total).toBe(2);
    expect(finished?.cpe_pairs_done).toBe(2);
  });

  it("records failure without losing the package scope", async () => {
    const nvd = {
      cvesForCpe: vi.fn().mockRejectedValue(new Error("upstream boom")),
    } as unknown as NvdClient;
    const job = await createVulnBackfillJob(pool, undefined, PKG);

    await expect(runVulnBackfillJob(pool, job.id, nvd)).rejects.toThrow("boom");

    const failed = await getVulnBackfillJob(pool, job.id);
    expect(failed?.status).toBe("failed");
    expect(failed?.package_name).toBe(PKG);
    expect(failed?.error_message).toMatch(/boom/);
  });
});
