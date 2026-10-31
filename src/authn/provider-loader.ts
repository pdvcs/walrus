import path from "node:path";
import type { AuthnProvider } from "./types.js";
import { createPasswordProvider } from "./providers/password.js";

export interface LoadAuthnProviderOptions {
  selection?: string;
  env: NodeJS.ProcessEnv;
  nodeEnv: "development" | "production" | "test";
  importModule?: (modulePath: string) => Promise<unknown>;
}

export async function loadAuthnProvider(options: LoadAuthnProviderOptions): Promise<AuthnProvider> {
  const selection = options.selection?.trim() || "password";
  let provider: AuthnProvider;

  if (selection === "password") {
    provider = createPasswordProvider({
      password: options.env.WALRUS_ADMIN_PASSWORD,
    });
  } else if (!isModulePath(selection)) {
    throw new Error(`Unknown authentication provider '${selection}'`);
  } else {
    const modulePath = path.isAbsolute(selection)
      ? selection
      : path.resolve(process.cwd(), selection);
    const imported = await (options.importModule ?? importAuthnModule)(modulePath);
    provider = extractProvider(imported, modulePath);
  }

  if (provider.apiVersion !== 1) {
    throw new Error(
      `Authentication provider '${provider.name}' has unsupported apiVersion ${String(provider.apiVersion)}; expected 1`,
    );
  }
  if (provider.configSchema) {
    const parsed = provider.configSchema.safeParse(options.env);
    if (!parsed.success) {
      throw new Error(
        `Invalid configuration for authentication provider '${provider.name}': ${parsed.error.message}`,
      );
    }
    await provider.init?.(parsed.data);
  } else {
    await provider.init?.(undefined);
  }
  return provider;
}

function isModulePath(selection: string): boolean {
  return path.isAbsolute(selection) || selection.startsWith("./") || selection.startsWith("../");
}

async function importAuthnModule(modulePath: string): Promise<unknown> {
  return import(modulePath);
}

function extractProvider(imported: unknown, modulePath: string): AuthnProvider {
  if (!imported || typeof imported !== "object") {
    throw new Error(`Authentication provider module '${modulePath}' has no provider export`);
  }
  const exports = imported as { default?: unknown; provider?: unknown };
  const candidate = exports.provider ?? exports.default;
  if (!isProvider(candidate)) {
    throw new Error(`Authentication provider module '${modulePath}' has no valid provider export`);
  }
  return candidate;
}

function isProvider(value: unknown): value is AuthnProvider {
  if (!value || typeof value !== "object") return false;
  const provider = value as Partial<AuthnProvider>;
  return (
    typeof provider.name === "string" &&
    typeof provider.apiVersion === "number" &&
    typeof provider.authenticate === "function"
  );
}
