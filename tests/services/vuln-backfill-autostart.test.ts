import { describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import {
  autoBackfillPendingPackages,
  findPackagesNeedingBackfill,
  hashCpePairs,
} from "../../src/services/vuln-backfill-autostart.js";
import { log } from "../../src/common/log.js";

/**
 * The detection SELECT returns one row per (package, CPE pair) with the package's stored
 * marker; `findPackagesNeedingBackfill` groups and compares in TypeScript. A `null` marker is
 * the "never covered" case, so every package named here comes back as pending.
 */
function poolWithPending(pending: Array<{ package_name: string; attempts: number }>) {
  const queries: string[] = [];
  const rows = pending.map((p) => ({
    package_name: p.package_name,
    cpe_vendor: p.package_name,
    cpe_product: "prod",
    stored_hash: null,
    attempts: p.attempts,
  }));
  const pool = {
    query: async (sql: string) => {
      queries.push(sql);
      // Only the detection SELECT returns rows; the UPDATEs return nothing.
      return { rows: sql.trimStart().startsWith("SELECT") ? rows : [] };
    },
  } as unknown as Pool;
  return { pool, queries };
}

describe("hashCpePairs", () => {
  it("is order-independent, so re-reading the same config is not seen as a change", () => {
    const a = hashCpePairs([
      { cpe_vendor: "golang", cpe_product: "go" },
      { cpe_vendor: "a", cpe_product: "b" },
    ]);
    const b = hashCpePairs([
      { cpe_vendor: "a", cpe_product: "b" },
      { cpe_vendor: "golang", cpe_product: "go" },
    ]);
    expect(a).toBe(b);
  });

  it("changes when a pair is added, which is what detects a widened package", () => {
    const before = hashCpePairs([{ cpe_vendor: "golang", cpe_product: "go" }]);
    const after = hashCpePairs([
      { cpe_vendor: "golang", cpe_product: "go" },
      { cpe_vendor: "google", cpe_product: "go" },
    ]);
    expect(after).not.toBe(before);
  });
});

/**
 * These pin the property that WAL-101 broke: the marker is compared against `hashCpePairs`
 * output, never against a digest computed anywhere else. The pairs below are `gitwindows`'
 * real ones — Postgres under `en_US.UTF8` orders them `git:git|git-scm:git` while JavaScript
 * orders them `git-scm:git|git:git`, so the old SQL-side digest could never match the marker
 * and the package was re-selected on every sweep for as long as the deployment lived.
 */
describe("findPackagesNeedingBackfill", () => {
  const GIT_PAIRS = [
    { cpe_vendor: "git-scm", cpe_product: "git" },
    { cpe_vendor: "git", cpe_product: "git" },
  ];

  function poolReturning(rows: unknown[]) {
    return {
      query: async () => ({ rows }),
    } as unknown as Pool;
  }

  function rowsFor(pairs: typeof GIT_PAIRS, stored: string | null, attempts = 0) {
    return pairs.map((p) => ({
      package_name: "gitwindows",
      cpe_vendor: p.cpe_vendor,
      cpe_product: p.cpe_product,
      stored_hash: stored,
      attempts,
    }));
  }

  it("does not re-select a package whose marker matches its own CPE pairs", async () => {
    const marker = hashCpePairs(GIT_PAIRS);
    const pending = await findPackagesNeedingBackfill(poolReturning(rowsFor(GIT_PAIRS, marker)));

    expect(pending).toEqual([]);
  });

  it("selects a package that has never been marked", async () => {
    const pending = await findPackagesNeedingBackfill(poolReturning(rowsFor(GIT_PAIRS, null)));

    expect(pending.map((p) => p.package_name)).toEqual(["gitwindows"]);
    expect(pending[0].cpe_hash).toBe(hashCpePairs(GIT_PAIRS));
  });

  it("selects a package again once a CPE pair is added to it", async () => {
    const marker = hashCpePairs(GIT_PAIRS);
    const widened = [...GIT_PAIRS, { cpe_vendor: "git", cpe_product: "git_for_windows" }];
    const pending = await findPackagesNeedingBackfill(poolReturning(rowsFor(widened, marker)));

    expect(pending.map((p) => p.package_name)).toEqual(["gitwindows"]);
  });

  it("orders by attempts then name, so the least-tried package is swept first", async () => {
    const rows = [
      { package_name: "uv", cpe_vendor: "uv", cpe_product: "uv", stored_hash: null, attempts: 2 },
      { package_name: "nodejs", cpe_vendor: "n", cpe_product: "n", stored_hash: null, attempts: 0 },
      { package_name: "golang", cpe_vendor: "g", cpe_product: "g", stored_hash: null, attempts: 0 },
    ];

    const pending = await findPackagesNeedingBackfill(poolReturning(rows));

    expect(pending.map((p) => p.package_name)).toEqual(["golang", "nodejs", "uv"]);
  });
});

describe("autoBackfillPendingPackages", () => {
  it("starts a backfill for an uncovered package without human action", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", attempts: 0 }]);
    const startVulnBackfill = vi.fn().mockResolvedValue({ job: { id: "job-1" } });

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(startVulnBackfill).toHaveBeenCalledWith(undefined, "golang");
    expect(result.started).toEqual(["golang"]);
    expect(result.failed).toEqual([]);
  });

  it("starts one and defers the rest, since only one backfill can be active", async () => {
    const { pool } = poolWithPending([
      { package_name: "golang", attempts: 0 },
      { package_name: "nodejs", attempts: 0 },
      { package_name: "uv", attempts: 0 },
    ]);
    const startVulnBackfill = vi.fn().mockResolvedValue({ job: { id: "job-1" } });

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(result.started).toEqual(["golang"]);
    expect(result.deferred).toEqual(["nodejs", "uv"]);
    expect(startVulnBackfill).toHaveBeenCalledTimes(1);
  });

  it("defers rather than failing when a backfill is already running", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", attempts: 0 }]);
    const startVulnBackfill = vi.fn().mockResolvedValue({ alreadyRunning: true });

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    // Contention is normal and must not burn the retry budget, or a busy period would
    // permanently exhaust a package's attempts and stop it being covered at all.
    expect(result.deferred).toEqual(["golang"]);
    expect(result.started).toEqual([]);
    expect(result.failed).toEqual([]);
  });

  it("reports a launch failure without aborting the sweep", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", attempts: 1 }]);
    const startVulnBackfill = vi.fn().mockRejectedValue(new Error("No CPE pairs"));

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(result.failed).toEqual([{ package: "golang", error: "No CPE pairs" }]);
    expect(result.started).toEqual([]);
  });

  it("emits an operator-visible error when a failure exhausts automatic retries", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", attempts: 2 }]);
    const startVulnBackfill = vi.fn().mockRejectedValue(new Error("No CPE pairs"));
    const error = vi.spyOn(log, "error").mockImplementation(() => undefined);

    await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(error).toHaveBeenCalledWith(
      expect.objectContaining({ package: "golang", attempts: 3 }),
      "Package exhausted automatic CVE backfill retries",
    );
    error.mockRestore();
  });

  it("does nothing when no package is missing coverage", async () => {
    const { pool } = poolWithPending([]);
    const startVulnBackfill = vi.fn();

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(result).toEqual({ pending: 0, started: [], deferred: [], failed: [] });
    expect(startVulnBackfill).not.toHaveBeenCalled();
  });
});
