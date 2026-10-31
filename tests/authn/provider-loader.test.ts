import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadAuthnProvider } from "../../src/authn/provider-loader.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) rmSync(directory, { recursive: true });
});

describe("authentication provider loader", () => {
  it("loads an adopter provider from an absolute module path and passes its env configuration", async () => {
    const directory = mkdtempSync(path.join(tmpdir(), "walrus-authn-"));
    temporaryDirectories.push(directory);
    const modulePath = path.join(directory, "provider.cjs");
    writeFileSync(
      modulePath,
      `module.exports.provider = {
        name: "fixture-directory",
        apiVersion: 1,
        configSchema: {
          safeParse(env) {
            return env.WALRUS_AUTHN_LDAP_URL
              ? { success: true, data: { url: env.WALRUS_AUTHN_LDAP_URL } }
              : { success: false, error: { message: "LDAP URL required" } };
          }
        },
        async init(config) { this.url = config.url; },
        async authenticate(credentials) {
          return { ok: true, subject: credentials.username + "@" + this.url };
        }
      };`,
    );

    const provider = await loadAuthnProvider({
      selection: modulePath,
      env: { WALRUS_AUTHN_LDAP_URL: "directory.example" },
      nodeEnv: "test",
    });
    await expect(provider.authenticate({ username: "alice", password: "secret" })).resolves.toEqual(
      { ok: true, subject: "alice@directory.example" },
    );
  });

  it("fails boot for an API mismatch, invalid export, schema rejection, or init error", async () => {
    const base = {
      name: "external",
      apiVersion: 1 as const,
      authenticate: async () => ({ ok: false as const, reason: "invalid_credentials" as const }),
    };
    const load = (moduleValue: unknown) =>
      loadAuthnProvider({
        selection: "./external.js",
        env: {},
        nodeEnv: "test",
        importModule: async () => moduleValue,
      });

    await expect(load({ default: { ...base, apiVersion: 2 } })).rejects.toThrow("apiVersion");
    await expect(load({ default: {} })).rejects.toThrow("valid provider export");
    await expect(
      load({
        default: {
          ...base,
          configSchema: { safeParse: () => ({ success: false, error: { message: "bad config" } }) },
        },
      }),
    ).rejects.toThrow("bad config");
    await expect(
      load({
        default: { ...base, init: vi.fn(async () => Promise.reject(new Error("bind failed"))) },
      }),
    ).rejects.toThrow("bind failed");
  });
});
