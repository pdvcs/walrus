import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const cloudRun = readFileSync(path.join(root, "infra/terraform/cloudrun.tf"), "utf8");

/**
 * WAL-95 AC4. Node's default old-space ceiling is roughly half the container, which sounds
 * conservative and is not: the JS heap is only one claimant, and Buffers — the transform's
 * LinkCache, the resumable-upload chunks — live outside it. Both can reach their maximum at once
 * and the container is OOM-killed with no stack. Each workload's ceiling is derived from what is
 * left after its Buffer budget, so heap + external + Node must fit the pin.
 *
 * The external figures below mirror the arithmetic in cloudrun.tf's comments. If a pin, a
 * concurrency or a chunk size changes without the ceiling following, this fails.
 */
const NODE_OVERHEAD_MIB = 80; // code, stacks, young generation, native allocations

const WORKLOADS = [
  // name,                container, external MiB (link cache + upload chunks)
  ["walrus-api service", 1024, 475 + 64],
  ["walrus-sync job", 2048, 1024 + 256],
  ["walrus-vuln-backfill job", 1024, 0],
] as const;

describe("container memory budget", () => {
  const heaps = [...cloudRun.matchAll(/--max-old-space-size=(\d+)/g)].map((m) => Number(m[1]));
  const pins = [...cloudRun.matchAll(/memory = "(\d+)Gi"/g)].map((m) => Number(m[1]) * 1024);

  it("gives every workload an explicit ceiling rather than Node's default", () => {
    expect(heaps).toHaveLength(3);
    expect(pins).toHaveLength(3);
  });

  it("leaves each workload's Buffer budget room outside the heap", () => {
    // Both lists are in file order, so index pairs them.
    const declared = heaps.map((heap, i) => ({ heap, pin: pins[i] }));
    for (const [name, container, external] of WORKLOADS) {
      const match = declared.find((d) => d.pin === container && d.heap + external < container);
      expect(
        match,
        `no workload fits ${name} (${container} MiB pin, ${external} MiB external)`,
      ).toBeDefined();
      expect(match!.heap + external + NODE_OVERHEAD_MIB).toBeLessThanOrEqual(container);
    }
  });

  it("keeps every ceiling below its own container", () => {
    for (const [i, heap] of heaps.entries()) expect(heap).toBeLessThan(pins[i]);
  });
});
