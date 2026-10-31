import pino from "pino";
import { describe, expect, it } from "vitest";

/**
 * WAL-120. pino runs its error serializer on the `err` key and no other. An Error passed under
 * any other key is serialized as a plain object — and `message` and `stack` are non-enumerable
 * on Error, so what reaches the log is `{}`. The line looks like it recorded something.
 *
 * The cost is larger than the missing field: Cloud Error Reporting groups by stack trace, so a
 * record carrying no stack enters no group and appears in no count. Four auth-path sites did
 * this, including both audit-failure logs, and were invisible in Error Reporting while every
 * other error in the project was grouped.
 *
 * These tests pin the mechanism rather than the spelling of the key, so the `no-restricted-syntax`
 * rule in `eslint.config.mjs` has something executable behind it. The second one fails if pino
 * ever starts serializing `error` too — at which point the rule can go.
 */

interface Captured {
  [key: string]: unknown;
}

function captureLogger(): { log: pino.Logger; lines: Captured[] } {
  const lines: Captured[] = [];
  const log = pino(
    { level: "trace" },
    {
      write(chunk: string) {
        lines.push(JSON.parse(chunk) as Captured);
      },
    },
  );
  return { log, lines };
}

describe("pino error serialization (WAL-120)", () => {
  it("serializes an Error under `err` with its type, message and stack", () => {
    const { log, lines } = captureLogger();

    log.error({ err: new Error("boom") }, "failed");

    const err = lines[0].err as { type: string; message: string; stack: string };
    expect(err.type).toBe("Error");
    expect(err.message).toBe("boom");
    // The stack is the field Error Reporting groups on; its absence is the whole defect.
    expect(err.stack).toContain("Error: boom");
  });

  it("discards an Error under any other key — the defect the lint rule exists to prevent", () => {
    const { log, lines } = captureLogger();

    log.error({ error: new Error("boom") }, "failed");

    // Not "missing some fields": the entire exception is gone.
    expect(lines[0].error).toEqual({});
  });

  it("keeps a non-Error value under `err` intact, so the convention costs nothing", () => {
    const { log, lines } = captureLogger();

    // Several call sites log an already-extracted string. Naming it `err` must not mangle it,
    // otherwise the rule would push authors toward a key that damages their value.
    log.warn({ err: "connection refused" }, "retrying");

    expect(lines[0].err).toBe("connection refused");
  });

  it("preserves a subclass name, so a typed failure stays distinguishable in a group", () => {
    const { log, lines } = captureLogger();

    class VulnSyncAlreadyRunningError extends Error {
      constructor() {
        super("vulnerability sync 'nvd' is already running");
        this.name = "VulnSyncAlreadyRunningError";
      }
    }
    log.error({ err: new VulnSyncAlreadyRunningError() }, "vuln sync failed");

    // Error Reporting files this as its own group, separate from genuine NVD failures, which is
    // what lets an operator resolve routine lock contention without muting anything real.
    const err = lines[0].err as { type: string; message: string };
    expect(err.type).toBe("VulnSyncAlreadyRunningError");
    expect(err.message).toContain("already running");
  });
});
