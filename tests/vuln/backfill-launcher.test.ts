import { describe, expect, it, vi } from "vitest";
import { LocalBackfillLauncher } from "../../src/vuln/backfill-launcher.js";
import type { Pool } from "pg";

describe("LocalBackfillLauncher", () => {
  it("returns immediately and runs the durable job asynchronously", async () => {
    const run = vi.fn().mockResolvedValue({ cves: 0, affects: 0, skippedCpes: 0 });
    const launcher = new LocalBackfillLauncher({} as Pool, run);

    await expect(launcher.launch("42")).resolves.toBe("local:42");
    expect(run).not.toHaveBeenCalled();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(run).toHaveBeenCalledWith(expect.anything(), "42");
  });
});
