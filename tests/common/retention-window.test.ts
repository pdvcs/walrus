import { describe, expect, it } from "vitest";
import {
  computeCoolingOffUntil,
  selectRetentionWindow,
} from "../../src/common/retention-window.js";
import { PackageConfig } from "../../src/types/package-config.js";
import { generateSortKey } from "../../src/common/version-utils.js";

const retention = { versions_per_group: 2, cooling_off_days: 3 } as PackageConfig["retention"];
const DAY = 86_400_000;
const threshold = generateSortKey("1.26.3");

describe("computeCoolingOffUntil", () => {
  it("anchors to the upstream release date when there is one", () => {
    const releasedAt = new Date(Date.now() - 1 * DAY);
    const until = computeCoolingOffUntil({ version: "1.27.0", releasedAt }, retention, threshold);
    expect(until?.getTime()).toBe(releasedAt.getTime() + 3 * DAY);
  });

  it("prefers the upstream release date over the first-seen anchor", () => {
    const releasedAt = new Date(Date.now() - 1 * DAY);
    const firstSeenAt = new Date(Date.now() - 2 * DAY);
    const until = computeCoolingOffUntil(
      { version: "1.27.0", releasedAt },
      retention,
      threshold,
      firstSeenAt,
    );
    expect(until?.getTime()).toBe(releasedAt.getTime() + 3 * DAY);
  });

  // WAL-91: the persisted embargo end is recomputed on every sync for as long as the artifact
  // stays pending. Anchored to the clock it advanced by one sync interval each run and was never
  // reached; anchored to first-seen it is the same instant no matter how often it is recomputed.
  it("returns the same embargo end however many times it is recomputed", async () => {
    const firstSeenAt = new Date(Date.now() - 1 * DAY);
    const first = computeCoolingOffUntil(
      { version: "1.27.0", releasedAt: undefined },
      retention,
      threshold,
      firstSeenAt,
    );
    await new Promise((r) => setTimeout(r, 10));
    const second = computeCoolingOffUntil(
      { version: "1.27.0", releasedAt: undefined },
      retention,
      threshold,
      firstSeenAt,
    );
    expect(second!.getTime()).toBe(first!.getTime());
    expect(first!.getTime()).toBe(firstSeenAt.getTime() + 3 * DAY);
  });

  it("lets the embargo elapse once cooling_off_days have passed since first discovery", () => {
    const firstSeenAt = new Date(Date.now() - 4 * DAY);
    const until = computeCoolingOffUntil(
      { version: "1.27.0", releasedAt: undefined },
      retention,
      threshold,
      firstSeenAt,
    );
    expect(until).toBeNull();
  });

  it("treats a version as embargoed when no anchor is available yet", () => {
    // Retention-window selection runs on discovery candidates, before any row exists to read
    // discovered_at from. Over-retaining is safe; dropping the version from the window is not.
    const until = computeCoolingOffUntil(
      { version: "1.27.0", releasedAt: undefined },
      retention,
      threshold,
    );
    expect(until).not.toBeNull();
    expect(until!.getTime()).toBeGreaterThan(Date.now());
  });

  it("does not embargo at or below the watermark, or during bootstrap", () => {
    const firstSeenAt = new Date();
    expect(
      computeCoolingOffUntil(
        { version: "1.26.3", releasedAt: undefined },
        retention,
        threshold,
        firstSeenAt,
      ),
    ).toBeNull();
    expect(
      computeCoolingOffUntil(
        { version: "1.27.0", releasedAt: undefined },
        retention,
        null,
        firstSeenAt,
      ),
    ).toBeNull();
  });

  it("releases a waived version immediately, whatever its anchor says", () => {
    const releasedAt = new Date(Date.now() - 1 * DAY);
    expect(
      computeCoolingOffUntil(
        { version: "1.27.0", releasedAt },
        retention,
        threshold,
        undefined,
        true,
      ),
    ).toBeNull();
    expect(
      computeCoolingOffUntil(
        { version: "1.27.0", releasedAt: undefined },
        retention,
        threshold,
        new Date(),
        true,
      ),
    ).toBeNull();
  });

  it("returns null when cooling off is not configured", () => {
    const none = { versions_per_group: 2 } as PackageConfig["retention"];
    expect(
      computeCoolingOffUntil(
        { version: "1.27.0", releasedAt: undefined },
        none,
        threshold,
        new Date(),
      ),
    ).toBeNull();
  });
});

describe("selectRetentionWindow", () => {
  it("keeps an embargoed version on top of the servable quota", () => {
    const versions = [
      { version: "1.27.0", versionGroup: "1.27" },
      { version: "1.26.3", versionGroup: "1.26" },
      { version: "1.26.2", versionGroup: "1.26" },
    ];
    const kept = selectRetentionWindow(versions, retention, generateSortKey("1.26.3")).map(
      (v) => v.version,
    );
    expect(kept).toContain("1.27.0");
    expect(kept).toContain("1.26.3");
    expect(kept).toContain("1.26.2");
  });
});

describe("selectRetentionWindow with a waiver", () => {
  it("counts a waived version against the servable quota instead of keeping it on top", () => {
    const versions = [
      { version: "1.27.0", versionGroup: "1.26" },
      { version: "1.26.3", versionGroup: "1.26" },
      { version: "1.26.2", versionGroup: "1.26" },
    ];
    const kept = (waived: string[]) =>
      selectRetentionWindow(versions, retention, generateSortKey("1.26.3"), new Set(waived)).map(
        (v) => v.version,
      );
    // Embargoed: retained on top of the quota, so all three survive.
    expect(kept([])).toEqual(["1.27.0", "1.26.3", "1.26.2"]);
    // Waived: it is servable now, so it takes a quota slot and the oldest is displaced.
    expect(kept(["1.27.0"])).toEqual(["1.27.0", "1.26.3"]);
  });
});
