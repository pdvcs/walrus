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

/**
 * WAL-98. `vuln_backfill_jobs.id` is BIGSERIAL and `db/client.ts` installs a global BIGINT type
 * parser, so the id arrives as a JS *number* however `BackfillLauncher.launch(jobId: string)`
 * types it. Postgres coerces either without complaint — which is why every other caller worked —
 * but the Cloud Run Jobs API type-checks the request body and rejected the launch with
 * `Invalid value at 'overrides.container_overrides[0].args[0]' (TYPE_STRING), 24`.
 *
 * Every autonomous backfill on GCP failed that way while the scheduler reported success, so what
 * this pins is the *wire* type, not the declared one. Only LocalBackfillLauncher had coverage
 * before, which is why nothing caught it.
 */
describe("CloudRunBackfillLauncher wire payload", () => {
  it("sends --job-id as a string even when the id arrives as a number", async () => {
    const saved = { ...process.env };
    process.env.GCP_PROJECT = "p";
    process.env.GCP_REGION = "r";
    process.env.VULN_BACKFILL_JOB = "walrus-vuln-backfill";
    // config/ is evaluated at import, so the module graph has to be rebuilt after setting these.
    vi.resetModules();
    const { CloudRunBackfillLauncher } = await import("../../src/vuln/backfill-launcher.js");

    let body: string | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: { body?: string }) => {
        if (String(url).includes("metadata.google.internal")) {
          return { ok: true, json: async () => ({ access_token: "t" }) } as unknown as Response;
        }
        body = init?.body;
        return { ok: true, json: async () => ({ name: "op/1" }) } as unknown as Response;
      }),
    );

    try {
      // The runtime reality: a number, despite the `string` signature.
      await new CloudRunBackfillLauncher().launch(24 as unknown as string);
      const args = JSON.parse(body!).overrides.containerOverrides[0].args as unknown[];
      expect(args).toEqual(["--job-id", "24"]);
      for (const a of args) expect(typeof a).toBe("string");
    } finally {
      vi.unstubAllGlobals();
      process.env = saved;
      vi.resetModules();
    }
  });
});
