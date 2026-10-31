import { describe, it, expect, beforeAll, afterAll, beforeEach } from "vitest";
import { Pool } from "pg";
import { runMigrations } from "../../src/db/client.js";
import { upsertPackage } from "../../src/db/queries/packages.js";
import {
  reconcilePackageVuln,
  listDistinctCpePairs,
} from "../../src/db/queries/package-aliases.js";
import { getVulnHints } from "../../src/services/vuln-hints.js";
import {
  findPackagesNeedingBackfill,
  hashCpePairs,
  markBackfillComplete,
  recordBackfillAttempt,
  MAX_ATTEMPTS,
} from "../../src/services/vuln-backfill-autostart.js";

const TEST_DB_URL =
  process.env.DATABASE_URL ?? "postgresql://walrus:walrus@localhost:5432/walrus_test";
const PKG = "hint-pkg";

async function seedTrackedPackage(pool: Pool, cpes: Array<{ v: string; p: string }>) {
  await upsertPackage(pool, {
    name: PKG,
    display_name: PKG,
    vendor: "T",
    description: null,
    website: null,
    config_hash: "h",
    enabled: true,
  });
  await reconcilePackageVuln(pool, {
    packageName: PKG,
    aliases: ["hint"],
    cpes: cpes.map((c) => ({ cpe_vendor: c.v, cpe_product: c.p, is_primary: true })),
    osvEcosystem: null,
    osvName: null,
  });
}

describe("autonomous backfill detection", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
  });

  /**
   * WAL-101. The marker used to be written from TypeScript (`hashCpePairs`) but recomputed in
   * SQL to select against, and the two disagreed whenever the pair ordering depended on
   * collation — the package then looked permanently uncovered and the sweep re-launched a
   * backfill for it on every run, forever.
   *
   * These are `gitwindows`' real pairs, the ones it happened to. Note that this test cannot
   * fail on a `C.UTF-8` database even against the old code: byte order and UTF-16 code-unit
   * order agree for ASCII, so only Cloud SQL's `en_US.UTF8` — which ignores punctuation at the
   * primary weight and sorts `git:git` first — showed the divergence. What protects the
   * behaviour now is structural: there is one digest implementation, so there is nothing left
   * to disagree. The round trip is asserted here because it is the property that matters.
   */
  it("stops selecting a package whose CPE pairs differ only by punctuation", async () => {
    await seedTrackedPackage(pool, [
      { v: "git-scm", p: "git" },
      { v: "git", p: "git" },
    ]);

    const pending = await findPackagesNeedingBackfill(pool);
    const row = pending.find((p) => p.package_name === PKG);
    expect(row).toBeDefined();
    expect(row!.cpe_hash).toBe(hashCpePairs(await listDistinctCpePairs(pool, PKG)));

    await markBackfillComplete(pool, PKG, row!.cpe_hash);

    expect((await findPackagesNeedingBackfill(pool)).map((r) => r.package_name)).not.toContain(PKG);
  });

  it("selects a newly tracked package, and stops once its CPE set is marked covered", async () => {
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    expect((await findPackagesNeedingBackfill(pool)).map((r) => r.package_name)).toContain(PKG);

    await markBackfillComplete(pool, PKG, hashCpePairs(await listDistinctCpePairs(pool, PKG)));
    expect((await findPackagesNeedingBackfill(pool)).map((r) => r.package_name)).not.toContain(PKG);
  });

  it("selects the package again when a CPE pair is added to it", async () => {
    // The case a bare "backfilled at" timestamp cannot see: already covered, then widened.
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    await markBackfillComplete(pool, PKG, hashCpePairs(await listDistinctCpePairs(pool, PKG)));

    await seedTrackedPackage(pool, [
      { v: "v", p: "p" },
      { v: "v2", p: "p2" },
    ]);

    expect((await findPackagesNeedingBackfill(pool)).map((r) => r.package_name)).toContain(PKG);
  });

  it("stops selecting a package once it exhausts its retry budget", async () => {
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    for (let i = 0; i < MAX_ATTEMPTS; i += 1) await recordBackfillAttempt(pool, PKG);

    expect((await findPackagesNeedingBackfill(pool)).map((r) => r.package_name)).not.toContain(PKG);
  });
});

describe("getVulnHints", () => {
  let pool: Pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: TEST_DB_URL });
    await runMigrations();
  });

  afterAll(async () => {
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
    await pool.end();
  });

  beforeEach(async () => {
    await pool.query(`DELETE FROM packages WHERE name = $1`, [PKG]);
  });

  it("stays silent for an uncovered package the sweep is still working on", async () => {
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    const hints = await getVulnHints(pool, { autoBackfillEnabled: true });
    expect(hints.join(" ")).not.toContain(PKG);
  });

  it("names the package when the sweep is switched off", async () => {
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    const hints = await getVulnHints(pool, { autoBackfillEnabled: false });
    expect(hints.join(" ")).toContain(PKG);
    expect(hints.join(" ")).toContain("VULN_AUTO_BACKFILL=false");
  });

  it("names the package once automatic retries are exhausted, even while enabled", async () => {
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    for (let i = 0; i < MAX_ATTEMPTS; i += 1) await recordBackfillAttempt(pool, PKG);

    const hints = await getVulnHints(pool, { autoBackfillEnabled: true });
    expect(hints.join(" ")).toContain(PKG);
    expect(hints.join(" ")).toContain("exhausted");
  });

  it("says nothing once the package is covered", async () => {
    await seedTrackedPackage(pool, [{ v: "v", p: "p" }]);
    await markBackfillComplete(pool, PKG, hashCpePairs(await listDistinctCpePairs(pool, PKG)));

    expect(await getVulnHints(pool, { autoBackfillEnabled: true })).toEqual([]);
  });
});
