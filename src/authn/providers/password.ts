import { createHash, timingSafeEqual } from "node:crypto";
import type { AuthnProvider } from "../types.js";

export interface PasswordProviderOptions {
  password: string | undefined;
}

export function createPasswordProvider(options: PasswordProviderOptions): AuthnProvider {
  validatePassword(options);
  const configuredDigest = digest(options.password!);

  return {
    name: "password",
    apiVersion: 1,
    authenticate(credentials) {
      const passwordMatches = timingSafeEqual(digest(credentials.password), configuredDigest);
      if (credentials.username !== "admin" || !passwordMatches) {
        return Promise.resolve({ ok: false, reason: "invalid_credentials" });
      }
      return Promise.resolve({ ok: true, subject: "admin", displayName: "Administrator" });
    },
  };
}

function validatePassword(options: PasswordProviderOptions): void {
  if (!options.password) throw new Error("WALRUS_ADMIN_PASSWORD is required");
  if (Buffer.byteLength(options.password, "utf8") < 16) {
    throw new Error("WALRUS_ADMIN_PASSWORD must be at least 16 bytes");
  }
}

function digest(value: string): Buffer {
  return createHash("sha256").update(value, "utf8").digest();
}
