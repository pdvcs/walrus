import { describe, expect, it, vi } from "vitest";
import { LocalSyncLauncher } from "../../src/services/sync-launcher.js";
import type { SyncService } from "../../src/services/sync-service.js";

describe("LocalSyncLauncher", () => {
  it("returns immediately and resumes the given job id asynchronously", async () => {
    const run = vi.fn().mockResolvedValue({ dryRun: false });
    const service = { run } as unknown as SyncService;
    const launcher = new LocalSyncLauncher((name) => (name === "uv" ? service : undefined));

    await expect(launcher.launch(42, "uv")).resolves.toBe("local:42");
    expect(run).not.toHaveBeenCalled();
    await new Promise<void>((resolve) => setImmediate(resolve));
    expect(run).toHaveBeenCalledWith({ triggerType: "admin", existingJobId: 42 });
  });

  it("rejects a package it has no SyncService for", () => {
    const launcher = new LocalSyncLauncher(() => undefined);
    expect(() => launcher.launch(1, "unknown")).toThrow(/Unknown package: unknown/);
  });
});

describe("CloudRunSyncLauncher", () => {
  it("passes the package name and job id as container override args", async () => {
    const saved = { ...process.env };
    process.env.GCP_PROJECT = "p";
    process.env.GCP_REGION = "r";
    process.env.SYNC_JOB = "walrus-sync";
    // config/ is evaluated at import, so the module graph has to be rebuilt after setting these.
    vi.resetModules();
    const { CloudRunSyncLauncher } = await import("../../src/services/sync-launcher.js");

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
      await new CloudRunSyncLauncher().launch(708, "rust");
      const args = JSON.parse(body!).overrides.containerOverrides[0].args as unknown[];
      expect(args).toEqual(["--package", "rust", "--job-id", "708"]);
      for (const a of args) expect(typeof a).toBe("string");
    } finally {
      vi.unstubAllGlobals();
      process.env = saved;
      vi.resetModules();
    }
  });

  it("fails clearly when SYNC_JOB is not configured", async () => {
    const saved = { ...process.env };
    delete process.env.SYNC_JOB;
    vi.resetModules();
    const { CloudRunSyncLauncher } = await import("../../src/services/sync-launcher.js");
    try {
      await expect(new CloudRunSyncLauncher().launch(1, "rust")).rejects.toThrow(/SYNC_JOB/);
    } finally {
      process.env = saved;
      vi.resetModules();
    }
  });
});
