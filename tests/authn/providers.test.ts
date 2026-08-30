import { describe, expect, it } from "vitest";
import { createPasswordProvider } from "../../src/authn/providers/password.js";
import { loadAuthnProvider } from "../../src/authn/provider-loader.js";

describe("password authentication provider", () => {
  it("accepts only admin with the configured password", async () => {
    const provider = createPasswordProvider({ password: "correct horse battery" });
    await expect(
      provider.authenticate({ username: "admin", password: "correct horse battery" }),
    ).resolves.toMatchObject({ ok: true, subject: "admin" });
    await expect(
      provider.authenticate({ username: "other", password: "correct horse battery" }),
    ).resolves.toEqual({ ok: false, reason: "invalid_credentials" });
    await expect(provider.authenticate({ username: "admin", password: "wrong" })).resolves.toEqual({
      ok: false,
      reason: "invalid_credentials",
    });
  });

  it("rejects unset and short passwords in every environment", () => {
    expect(() => createPasswordProvider({ password: undefined })).toThrow("required");
    expect(() => createPasswordProvider({ password: "too-short" })).toThrow("at least 16 bytes");
  });

  it("uses the built-in provider only when explicitly selected or unset", async () => {
    const provider = await loadAuthnProvider({
      env: { WALRUS_ADMIN_PASSWORD: "correct horse battery" },
      nodeEnv: "test",
    });
    expect(provider.name).toBe("password");
    await expect(
      loadAuthnProvider({ selection: "ldap", env: {}, nodeEnv: "test" }),
    ).rejects.toThrow("Unknown authentication provider");
  });

  it("never falls back when the selected provider reports unavailable", async () => {
    const external = {
      name: "directory",
      apiVersion: 1 as const,
      authenticate: async () => ({ ok: false as const, reason: "unavailable" as const }),
    };
    const provider = await loadAuthnProvider({
      selection: "./directory.js",
      env: { WALRUS_ADMIN_PASSWORD: "fallback password" },
      nodeEnv: "test",
      importModule: async () => ({ default: external }),
    });
    await expect(
      provider.authenticate({ username: "admin", password: "fallback password" }),
    ).resolves.toEqual({ ok: false, reason: "unavailable" });
  });
});
