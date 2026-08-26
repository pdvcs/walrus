import { describe, it, expect } from "vitest";
import {
  computeSyncDegradations,
  STALENESS_THRESHOLDS_MS,
} from "../../src/services/degradations.js";
import type { VulnSourceStatus, VulnSyncStatus } from "../../src/db/queries/vuln-sync-state.js";

const NOW = new Date("2026-08-26T12:00:00.000Z");

function iso(msAgo: number): string {
  return new Date(NOW.getTime() - msAgo).toISOString();
}

function healthy(msAgo = 3_600_000): VulnSourceStatus {
  return {
    last_attempt: iso(msAgo),
    last_success: iso(msAgo),
    last_failure: null,
    last_ok: true,
  };
}

function status(overrides: Partial<VulnSyncStatus> = {}): VulnSyncStatus {
  return {
    nvd: healthy(),
    kev: healthy(),
    osv: healthy(),
    ...overrides,
  };
}

describe("computeSyncDegradations", () => {
  it("reports nothing when every source succeeded recently", () => {
    expect(computeSyncDegradations(status(), NOW)).toEqual([]);
  });

  it("flags a source whose last success is beyond its threshold", () => {
    const s = status({ nvd: healthy(STALENESS_THRESHOLDS_MS.nvd + 3_600_000) });
    const out = computeSyncDegradations(s, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].component).toBe("vuln-sync-nvd");
    expect(out[0].reason).toContain("last succeeded");
  });

  it("stays quiet inside the threshold — a missed run or two is not degradation", () => {
    // 2-hourly cadence, 11h old: several runs missed but under the 12h threshold.
    const s = status({ nvd: healthy(11 * 3_600_000) });
    expect(computeSyncDegradations(s, NOW)).toEqual([]);
  });

  it("uses per-source thresholds: a 3-day-old OSV sync is fine, a 3-day-old KEV sync is not", () => {
    const threeDays = 3 * 24 * 3_600_000;
    const s = status({ osv: healthy(threeDays), kev: healthy(threeDays) });
    const out = computeSyncDegradations(s, NOW);
    expect(out.map((d) => d.component)).toEqual(["vuln-sync-kev"]);
  });

  it("flags a source that has never succeeded", () => {
    const s = status({
      kev: { last_attempt: iso(60_000), last_success: null, last_failure: iso(60_000), last_ok: false },
    });
    const out = computeSyncDegradations(s, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].component).toBe("vuln-sync-kev");
    expect(out[0].reason).toContain("never completed successfully");
  });

  it("flags a currently-failing source even before it turns stale", () => {
    const s = status({
      osv: {
        last_attempt: iso(60_000),
        last_success: iso(24 * 3_600_000), // well inside osv's 8-day threshold
        last_failure: iso(60_000),
        last_ok: false,
      },
    });
    const out = computeSyncDegradations(s, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].component).toBe("vuln-sync-osv");
    expect(out[0].reason).toContain("failed");
  });

  it("reports one entry per source, not one per symptom", () => {
    // Stale AND failing: staleness (with the failure folded into its reason) wins.
    const s = status({
      nvd: {
        last_attempt: iso(60_000),
        last_success: iso(STALENESS_THRESHOLDS_MS.nvd + 3_600_000),
        last_failure: iso(60_000),
        last_ok: false,
      },
    });
    const out = computeSyncDegradations(s, NOW);
    expect(out).toHaveLength(1);
    expect(out[0].reason).toContain("last succeeded");
    expect(out[0].reason).toContain("failed");
  });
});
