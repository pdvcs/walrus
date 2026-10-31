import { createAdminRoster } from "../../src/authn/admins.js";
import type { OperatorAuthRuntime } from "../../src/authn/runtime.js";
import { mintSession } from "../../src/authn/session.js";

export function testOperatorAuth(subject = "admin"): {
  runtime: OperatorAuthRuntime;
  bearer: string;
} {
  const sessions = {
    currentKey: Buffer.from("01234567890123456789012345678901"),
    ttlSeconds: 7200,
    maxSeconds: 28_800,
    epoch: 1,
  };
  const runtime: OperatorAuthRuntime = {
    provider: {
      name: "test",
      apiVersion: 1,
      authenticate: async () => ({ ok: true, subject }),
    },
    roster: createAdminRoster([subject], "exact"),
    sessions,
    keyFingerprint: "12345678",
    nodeEnv: "development",
    minimumLoginMs: 0,
  };
  return { runtime, bearer: mintSession(subject, "bearer", sessions).token };
}
