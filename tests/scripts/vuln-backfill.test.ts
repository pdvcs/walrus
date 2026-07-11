import { describe, expect, it } from "vitest";
import { parseSince } from "../../scripts/vuln-backfill.js";
import { buildPublicationWindows } from "../../src/vuln/sync/nvd-sync.js";

describe("vulnerability backfill date handling", () => {
  it("parses --since and rejects a missing value", () => {
    expect(parseSince([])).toBeUndefined();
    expect(parseSince(["--since", "2025-01-01"])).toBe("2025-01-01");
    expect(() => parseSince(["--since"])).toThrow(/requires/);
    expect(() => parseSince(["--since", "2025-02-30"])).toThrow(/Invalid/);
    expect(() => parseSince(["--since", "2999-01-01"])).toThrow(/future/);
  });

  it("builds one paired publication window for a short range", () => {
    expect(buildPublicationWindows("2025-05-01", new Date("2025-05-15T12:00:00.000Z"))).toEqual([
      {
        pubStartDate: "2025-05-01T00:00:00.000Z",
        pubEndDate: "2025-05-15T12:00:00.000Z",
      },
    ]);
  });

  it("splits long ranges into adjacent windows no longer than 120 days", () => {
    const windows = buildPublicationWindows("2024-01-01", new Date("2025-01-15T12:00:00.000Z"));

    expect(windows.length).toBeGreaterThan(1);
    expect(windows[0].pubStartDate).toBe("2024-01-01T00:00:00.000Z");
    expect(windows.at(-1)?.pubEndDate).toBe("2025-01-15T12:00:00.000Z");
    for (let i = 0; i < windows.length; i++) {
      const start = Date.parse(windows[i].pubStartDate);
      const end = Date.parse(windows[i].pubEndDate);
      expect(end - start).toBeLessThanOrEqual(119 * 24 * 3600 * 1000);
      if (i > 0) expect(start).toBe(Date.parse(windows[i - 1].pubEndDate) + 1);
    }
  });

  it("rejects impossible and future dates", () => {
    const now = new Date("2025-05-15T12:00:00.000Z");
    expect(() => buildPublicationWindows("2025-02-30", now)).toThrow(/Invalid/);
    expect(() => buildPublicationWindows("not-a-date", now)).toThrow(/Invalid/);
    expect(() => buildPublicationWindows("2025-05-16", now)).toThrow(/future/);
  });
});
