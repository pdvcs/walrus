import { describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import {
  autoBackfillPendingPackages,
  hashCpePairs,
} from "../../src/services/vuln-backfill-autostart.js";
import { log } from "../../src/common/log.js";

function poolWithPending(
  pending: Array<{ package_name: string; cpe_hash: string; attempts: number }>,
) {
  const queries: string[] = [];
  const pool = {
    query: async (sql: string) => {
      queries.push(sql);
      // Only the detection SELECT returns rows; the UPDATEs return nothing.
      return { rows: sql.trimStart().startsWith("SELECT") ? pending : [] };
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

describe("autoBackfillPendingPackages", () => {
  it("starts a backfill for an uncovered package without human action", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", cpe_hash: "h", attempts: 0 }]);
    const startVulnBackfill = vi.fn().mockResolvedValue({ job: { id: "job-1" } });

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(startVulnBackfill).toHaveBeenCalledWith(undefined, "golang");
    expect(result.started).toEqual(["golang"]);
    expect(result.failed).toEqual([]);
  });

  it("starts one and defers the rest, since only one backfill can be active", async () => {
    const { pool } = poolWithPending([
      { package_name: "golang", cpe_hash: "h", attempts: 0 },
      { package_name: "nodejs", cpe_hash: "h", attempts: 0 },
      { package_name: "uv", cpe_hash: "h", attempts: 0 },
    ]);
    const startVulnBackfill = vi.fn().mockResolvedValue({ job: { id: "job-1" } });

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(result.started).toEqual(["golang"]);
    expect(result.deferred).toEqual(["nodejs", "uv"]);
    expect(startVulnBackfill).toHaveBeenCalledTimes(1);
  });

  it("defers rather than failing when a backfill is already running", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", cpe_hash: "h", attempts: 0 }]);
    const startVulnBackfill = vi.fn().mockResolvedValue({ alreadyRunning: true });

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    // Contention is normal and must not burn the retry budget, or a busy period would
    // permanently exhaust a package's attempts and stop it being covered at all.
    expect(result.deferred).toEqual(["golang"]);
    expect(result.started).toEqual([]);
    expect(result.failed).toEqual([]);
  });

  it("reports a launch failure without aborting the sweep", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", cpe_hash: "h", attempts: 1 }]);
    const startVulnBackfill = vi.fn().mockRejectedValue(new Error("No CPE pairs"));

    const result = await autoBackfillPendingPackages(pool, { startVulnBackfill });

    expect(result.failed).toEqual([{ package: "golang", error: "No CPE pairs" }]);
    expect(result.started).toEqual([]);
  });

  it("emits an operator-visible error when a failure exhausts automatic retries", async () => {
    const { pool } = poolWithPending([{ package_name: "golang", cpe_hash: "h", attempts: 2 }]);
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
