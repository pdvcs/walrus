import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadOperatorAuthRuntime } from "../../src/authn/runtime.js";
import { config, type AppConfig } from "../../src/config/index.js";

const directory = mkdtempSync(path.join(tmpdir(), "walrus-runtime-"));
const rosterPath = path.join(directory, "admins.toml");
const password = "correct horse battery staple";

function appConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    ...config,
    NODE_ENV: "test",
    WALRUS_AUTHN_PROVIDER: "password",
    WALRUS_ADMINS_FILE: rosterPath,
    WALRUS_ADMIN_MATCH: "fold",
    WALRUS_SESSION_SECRET: "01234567890123456789012345678901",
    WALRUS_SESSION_SECRET_PREVIOUS: undefined,
    WALRUS_SESSION_TTL_SECONDS: 120,
    WALRUS_SESSION_MAX_SECONDS: 480,
    WALRUS_SESSION_EPOCH: 2,
    ...overrides,
  };
}

describe("operator authentication runtime", () => {
  beforeAll(() => writeFileSync(rosterPath, 'admins = ["Admin"]\n'));
  afterAll(() => rmSync(directory, { recursive: true }));

  it("composes the provider, normalized roster, session keys, and audit callbacks", async () => {
    const auditLogin = async () => undefined;
    const auditAction = async () => undefined;
    const runtime = await loadOperatorAuthRuntime(
      appConfig({ WALRUS_SESSION_SECRET_PREVIOUS: "previous-01234567890123456789012" }),
      { env: { WALRUS_ADMIN_PASSWORD: password }, auditLogin, auditAction },
    );

    expect(runtime.provider.name).toBe("password");
    expect(runtime.roster.has("admin")).toBe(true);
    expect(runtime.sessions.currentKey).toHaveLength(32);
    expect(runtime.sessions.previousKey?.length).toBeGreaterThanOrEqual(32);
    expect(runtime.sessions).toMatchObject({ ttlSeconds: 120, maxSeconds: 480, epoch: 2 });
    expect(runtime.keyFingerprint).toMatch(/^[0-9a-f]{8}$/);
    expect(runtime.auditLogin).toBe(auditLogin);
    expect(runtime.auditAction).toBe(auditAction);
  });

  it("requires a configured session secret in production", async () => {
    await expect(
      loadOperatorAuthRuntime(
        appConfig({ NODE_ENV: "production", WALRUS_SESSION_SECRET: undefined }),
        {
          env: { WALRUS_ADMIN_PASSWORD: password },
        },
      ),
    ).rejects.toThrow("WALRUS_SESSION_SECRET is required in production");
  });

  it("rejects short current and previous secrets and an inverted lifetime", async () => {
    const load = (overrides: Partial<AppConfig>) =>
      loadOperatorAuthRuntime(appConfig(overrides), {
        env: { WALRUS_ADMIN_PASSWORD: password },
      });
    await expect(load({ WALRUS_SESSION_SECRET: "short" })).rejects.toThrow("at least 32 bytes");
    await expect(load({ WALRUS_SESSION_SECRET_PREVIOUS: "short" })).rejects.toThrow(
      "WALRUS_SESSION_SECRET_PREVIOUS must be at least 32 bytes",
    );
    await expect(
      load({ WALRUS_SESSION_TTL_SECONDS: 481, WALRUS_SESSION_MAX_SECONDS: 480 }),
    ).rejects.toThrow("MAX_SECONDS must be at least");
  });

  it("uses a fresh process-local key when a non-production secret is unset", async () => {
    const options = { env: { WALRUS_ADMIN_PASSWORD: password } };
    const first = await loadOperatorAuthRuntime(
      appConfig({ WALRUS_SESSION_SECRET: undefined }),
      options,
    );
    const second = await loadOperatorAuthRuntime(
      appConfig({ WALRUS_SESSION_SECRET: undefined }),
      options,
    );
    expect(first.sessions.currentKey).toHaveLength(32);
    expect(first.sessions.currentKey.equals(second.sessions.currentKey)).toBe(false);
    expect(first.keyFingerprint).not.toBe(second.keyFingerprint);
  });
});
