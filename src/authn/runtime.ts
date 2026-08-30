import { randomBytes } from "node:crypto";
import path from "node:path";
import type { AppConfig } from "../config/index.js";
import { log } from "../common/log.js";
import { loadAdminRoster, type AdminRoster } from "./admins.js";
import { loadAuthnProvider } from "./provider-loader.js";
import { sessionKeyFingerprint, type SessionConfig, type SessionKind } from "./session.js";
import type { AuthnProvider } from "./types.js";

export interface LoginAuditEvent {
  outcome: "success" | "invalid_credentials" | "forbidden" | "unavailable";
  username: string;
  provider: string;
  ip: string;
  subject?: string;
}

export interface OperatorActionAuditEvent {
  subject: string;
  kind: SessionKind;
  method: string;
  path: string;
  status: number;
}

export interface OperatorAuthRuntime {
  provider: AuthnProvider;
  roster: AdminRoster;
  sessions: SessionConfig;
  keyFingerprint: string;
  nodeEnv: "development" | "production" | "test";
  now?: () => Date;
  minimumLoginMs?: number;
  loginTiming?: {
    now: () => number;
    sleep: (milliseconds: number) => Promise<void>;
  };
  auditLogin?: (event: LoginAuditEvent) => Promise<void>;
  auditAction?: (event: OperatorActionAuditEvent) => Promise<void>;
}

export async function loadOperatorAuthRuntime(
  config: AppConfig,
  options: {
    env?: NodeJS.ProcessEnv;
    auditLogin?: OperatorAuthRuntime["auditLogin"];
    auditAction?: OperatorAuthRuntime["auditAction"];
  } = {},
): Promise<OperatorAuthRuntime> {
  const env = options.env ?? process.env;
  const provider = await loadAuthnProvider({
    selection: config.WALRUS_AUTHN_PROVIDER,
    env,
    nodeEnv: config.NODE_ENV,
  });
  const roster = loadAdminRoster(
    path.resolve(config.WALRUS_ADMINS_FILE),
    config.WALRUS_ADMIN_MATCH,
  );
  const currentKey = sessionKey(config.WALRUS_SESSION_SECRET, config.NODE_ENV, "current");
  const previousKey = config.WALRUS_SESSION_SECRET_PREVIOUS
    ? Buffer.from(config.WALRUS_SESSION_SECRET_PREVIOUS, "utf8")
    : undefined;
  const sessions: SessionConfig = {
    currentKey,
    previousKey,
    ttlSeconds: config.WALRUS_SESSION_TTL_SECONDS,
    maxSeconds: config.WALRUS_SESSION_MAX_SECONDS,
    epoch: config.WALRUS_SESSION_EPOCH,
  };
  // Validate all lifetime and key constraints during boot, before the first login.
  const fingerprint = sessionKeyFingerprint(sessions.currentKey);
  if (sessions.previousKey && sessions.previousKey.length < 32) {
    throw new Error("WALRUS_SESSION_SECRET_PREVIOUS must be at least 32 bytes");
  }
  if (sessions.maxSeconds < sessions.ttlSeconds) {
    throw new Error("WALRUS_SESSION_MAX_SECONDS must be at least WALRUS_SESSION_TTL_SECONDS");
  }
  log.info({ provider: provider.name, sessionKeyFingerprint: fingerprint }, "Authentication ready");
  return {
    provider,
    roster,
    sessions,
    keyFingerprint: fingerprint,
    nodeEnv: config.NODE_ENV,
    auditLogin: options.auditLogin,
    auditAction: options.auditAction,
  };
}

function sessionKey(
  configured: string | undefined,
  nodeEnv: AppConfig["NODE_ENV"],
  label: string,
): Buffer {
  if (configured) {
    const key = Buffer.from(configured, "utf8");
    if (key.length < 32) throw new Error(`WALRUS_SESSION_SECRET must be at least 32 bytes`);
    return key;
  }
  if (nodeEnv === "production") throw new Error("WALRUS_SESSION_SECRET is required in production");
  const key = randomBytes(32);
  log.warn(
    { key: label },
    "WALRUS_SESSION_SECRET is unset; generated a process-local key unsuitable for multiple instances",
  );
  return key;
}
