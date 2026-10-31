import { createHash, createHmac, timingSafeEqual } from "node:crypto";

export type SessionKind = "cookie" | "bearer";

export interface SessionPayload {
  sub: string;
  iat: number;
  exp: number;
  cap: number;
  epoch: number;
  k: SessionKind;
  v: 1;
}

export interface SessionConfig {
  currentKey: Buffer;
  previousKey?: Buffer;
  ttlSeconds: number;
  maxSeconds: number;
  epoch: number;
  clockSkewSeconds?: number;
}

export type SessionVerification =
  | { ok: true; payload: SessionPayload; signedWith: "current" | "previous" }
  | {
      ok: false;
      reason:
        | "malformed"
        | "invalid_signature"
        | "invalid_payload"
        | "expired"
        | "future_issued"
        | "wrong_epoch"
        | "wrong_kind";
    };

export function mintSession(
  subject: string,
  kind: SessionKind,
  config: SessionConfig,
  now = new Date(),
): { token: string; payload: SessionPayload } {
  validateConfig(config);
  const iat = epochSeconds(now);
  const cap = iat + config.maxSeconds;
  const payload: SessionPayload = {
    sub: subject,
    iat,
    exp: kind === "bearer" ? cap : Math.min(iat + config.ttlSeconds, cap),
    cap,
    epoch: config.epoch,
    k: kind,
    v: 1,
  };
  return { token: signPayload(payload, config.currentKey), payload };
}

export function verifySession(
  token: string,
  config: SessionConfig,
  opts: { now?: Date; expectedKind?: SessionKind } = {},
): SessionVerification {
  validateConfig(config);
  const segments = token.split(".");
  if (segments.length !== 2 || !segments[0] || !segments[1]) return failure("malformed");

  let actualSignature: Buffer;
  try {
    actualSignature = Buffer.from(segments[1], "base64url");
  } catch {
    return failure("malformed");
  }
  if (actualSignature.length !== 32) return failure("invalid_signature");

  const currentSignature = signature(segments[0], config.currentKey);
  let signedWith: "current" | "previous" | undefined;
  if (timingSafeEqual(actualSignature, currentSignature)) {
    signedWith = "current";
  } else if (config.previousKey) {
    const previousSignature = signature(segments[0], config.previousKey);
    if (timingSafeEqual(actualSignature, previousSignature)) signedWith = "previous";
  }
  if (!signedWith) return failure("invalid_signature");

  let payload: unknown;
  try {
    payload = JSON.parse(Buffer.from(segments[0], "base64url").toString("utf8"));
  } catch {
    return failure("invalid_payload");
  }
  if (!isSessionPayload(payload)) return failure("invalid_payload");

  const nowSeconds = epochSeconds(opts.now ?? new Date());
  const clockSkew = config.clockSkewSeconds ?? 60;
  if (payload.iat > nowSeconds + clockSkew) return failure("future_issued");
  if (payload.exp <= nowSeconds || payload.cap <= nowSeconds) return failure("expired");
  if (payload.epoch !== config.epoch) return failure("wrong_epoch");
  if (opts.expectedKind && payload.k !== opts.expectedKind) return failure("wrong_kind");
  return { ok: true, payload, signedWith };
}

export function renewSession(
  payload: SessionPayload,
  config: SessionConfig,
  now = new Date(),
): { token: string; payload: SessionPayload } | null {
  validateConfig(config);
  if (payload.k !== "cookie") return null;
  const current = epochSeconds(now);
  if (payload.exp <= current || payload.cap <= current) return null;
  if (current < payload.exp - config.ttlSeconds / 2) return null;

  const renewed: SessionPayload = {
    ...payload,
    exp: Math.min(current + config.ttlSeconds, payload.cap),
  };
  return { token: signPayload(renewed, config.currentKey), payload: renewed };
}

export function sessionKeyFingerprint(key: Buffer): string {
  return createHash("sha256").update(key).digest("hex").slice(0, 8);
}

function signPayload(payload: SessionPayload, key: Buffer): string {
  const encoded = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  return `${encoded}.${signature(encoded, key).toString("base64url")}`;
}

function signature(encodedPayload: string, key: Buffer): Buffer {
  return createHmac("sha256", key).update(encodedPayload).digest();
}

function epochSeconds(value: Date): number {
  return Math.floor(value.getTime() / 1000);
}

function validateConfig(config: SessionConfig): void {
  if (config.currentKey.length < 32) throw new Error("Session key must be at least 32 bytes");
  if (config.previousKey && config.previousKey.length < 32) {
    throw new Error("Previous session key must be at least 32 bytes");
  }
  if (!Number.isInteger(config.ttlSeconds) || config.ttlSeconds <= 0) {
    throw new Error("Session TTL must be a positive integer");
  }
  if (!Number.isInteger(config.maxSeconds) || config.maxSeconds < config.ttlSeconds) {
    throw new Error("Session maximum must be an integer at least as large as the TTL");
  }
  if (!Number.isInteger(config.epoch) || config.epoch < 0) {
    throw new Error("Session epoch must be a non-negative integer");
  }
}

function isSessionPayload(value: unknown): value is SessionPayload {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const payload = value as Record<string, unknown>;
  return (
    Object.keys(payload).length === 7 &&
    typeof payload.sub === "string" &&
    payload.sub.length > 0 &&
    isInteger(payload.iat) &&
    isInteger(payload.exp) &&
    isInteger(payload.cap) &&
    payload.exp <= payload.cap &&
    isInteger(payload.epoch) &&
    payload.epoch >= 0 &&
    (payload.k === "cookie" || payload.k === "bearer") &&
    payload.v === 1
  );
}

function isInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

function failure(
  reason: Extract<SessionVerification, { ok: false }>["reason"],
): SessionVerification {
  return { ok: false, reason };
}
