import { describe, expect, it } from "vitest";
import { Pool } from "pg";
import {
  backfillDisabledHint,
  backfillStuckHint,
  getVulnHints,
} from "../../src/services/vuln-hints.js";

/**
 * `vuln-hints.ts` had no test at all, which is why its global check survived: it only
 * fired when `cve_affects` was empty across the whole database, so a package added after
 * the first backfill was never flagged. These pin the per-package behaviour.
 */
function poolReturning(rows: Array<{ name: string; attempts: number; last_error: string | null }>) {
  return { query: async () => ({ rows }) } as unknown as Pool;
}

describe("getVulnHints", () => {
  it("says nothing when every package with CPEs has been backfilled", async () => {
    expect(await getVulnHints(poolReturning([]))).toEqual([]);
  });

  it("stays silent for a package still within its automatic retry budget", async () => {
    // Walrus is closing this gap itself; nagging an operator about work already in hand
    // is how a hint becomes noise that gets ignored.
    const hints = await getVulnHints(
      poolReturning([{ name: "golang", attempts: 1, last_error: null }]),
      {
        autoBackfillEnabled: true,
      },
    );
    expect(hints).toEqual([]);
  });

  it("flags a package only once automatic retries are exhausted", async () => {
    const hints = await getVulnHints(
      poolReturning([{ name: "golang", attempts: 3, last_error: "NVD 503" }]),
      { autoBackfillEnabled: true },
    );
    expect(hints).toHaveLength(1);
    expect(hints[0]).toContain("golang");
    expect(hints[0]).toContain("NVD 503");
  });

  it("flags uncovered packages when the sweep has been switched off", async () => {
    const hints = await getVulnHints(
      poolReturning([{ name: "ripgrep", attempts: 0, last_error: null }]),
      { autoBackfillEnabled: false },
    );
    expect(hints).toHaveLength(1);
    expect(hints[0]).toContain("VULN_AUTO_BACKFILL=false");
    expect(hints[0]).toContain("ripgrep");
  });

  it("never tells production to run an npm script it cannot run", async () => {
    // The image installs no dev dependencies and never copies scripts/, so the old
    // "run `npm run vuln:backfill`" remedy was unactionable exactly where it appeared.
    const texts = [
      backfillDisabledHint(["golang"]),
      backfillStuckHint([{ name: "golang", error: null }]),
    ];
    for (const text of texts) {
      expect(text).not.toContain("npm run");
    }
  });
});
