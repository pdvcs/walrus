import { createPublicKey, verify as verifySignature, type JsonWebKey } from "node:crypto";
import type { RequestHandler } from "express";
import type { AppConfig } from "../config/index.js";
import { log } from "../common/log.js";

const GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const DEFAULT_JWKS_TTL_MS = 60 * 60 * 1000;

interface GoogleIdTokenHeader {
  alg: string;
  kid: string;
}

interface GoogleIdTokenClaims {
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  email: string;
  email_verified?: boolean;
  sub?: string;
}

interface JwksDocument {
  keys: JsonWebKey[];
}

export interface MachineAuditEvent {
  subject: string;
  method: string;
  path: string;
  status: number;
}

export type MachineVerification =
  | { ok: true; principal: string; claims: GoogleIdTokenClaims }
  | { ok: false; status: 401 | 403; reason: string };

export class GoogleOidcVerifier {
  private keys = new Map<string, JsonWebKey>();
  private keysExpireAt = 0;
  private keysRequest?: Promise<void>;
  private lastUnknownKeyRefresh = 0;

  constructor(
    private readonly options: {
      audience: string;
      serviceAccount: string;
      fetch?: typeof fetch;
      now?: () => Date;
      jwksUrl?: string;
    },
  ) {}

  async verify(token: string): Promise<MachineVerification> {
    if (token.length > 16_384) return unauthorized("OIDC token is too large");
    const parts = token.split(".");
    if (parts.length !== 3) return unauthorized("Malformed OIDC token");
    const header = decodeJson<GoogleIdTokenHeader>(parts[0]);
    const claims = decodeJson<GoogleIdTokenClaims>(parts[1]);
    if (!header || !claims || header.alg !== "RS256" || !header.kid) {
      return unauthorized("Unsupported OIDC token");
    }

    let key: JsonWebKey | undefined;
    try {
      key = await this.key(header.kid);
    } catch (error) {
      log.error({ error }, "Unable to refresh Google OIDC signing keys");
      return unauthorized("OIDC signing keys unavailable");
    }
    if (!key) return unauthorized("Unknown OIDC signing key");

    const signature = decodeBase64Url(parts[2]);
    if (!signature) return unauthorized("Malformed OIDC signature");
    let signatureValid = false;
    try {
      signatureValid = verifySignature(
        "RSA-SHA256",
        Buffer.from(`${parts[0]}.${parts[1]}`),
        createPublicKey({ key, format: "jwk" }),
        signature,
      );
    } catch {
      return unauthorized("Invalid OIDC signing key");
    }
    if (!signatureValid) return unauthorized("Invalid OIDC signature");

    const now = Math.floor((this.options.now?.() ?? new Date()).getTime() / 1000);
    if (!["accounts.google.com", "https://accounts.google.com"].includes(claims.iss)) {
      return unauthorized("Invalid OIDC issuer");
    }
    if (!Number.isInteger(claims.exp) || claims.exp <= now) {
      return unauthorized("Expired OIDC token");
    }
    if (!Number.isInteger(claims.iat) || claims.iat > now + 60) {
      return unauthorized("Invalid OIDC issue time");
    }
    const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
    if (!audiences.includes(this.options.audience)) {
      return forbidden("OIDC audience is not allowed");
    }
    if (claims.email_verified !== true || claims.email !== this.options.serviceAccount) {
      return forbidden("OIDC principal is not allowed");
    }
    return { ok: true, principal: claims.email, claims };
  }

  private async key(kid: string): Promise<JsonWebKey | undefined> {
    const now = (this.options.now?.() ?? new Date()).getTime();
    if (now >= this.keysExpireAt) {
      await this.refreshKeys();
      return this.keys.get(kid);
    }
    if (!this.keys.has(kid) && now - this.lastUnknownKeyRefresh >= 60_000) {
      // Accommodate Google key rotation without letting random public `kid` values turn into
      // an unbounded stream of outbound JWKS requests.
      this.lastUnknownKeyRefresh = now;
      await this.refreshKeys();
    }
    return this.keys.get(kid);
  }

  private async refreshKeys(): Promise<void> {
    if (this.keysRequest) return this.keysRequest;
    this.keysRequest = this.fetchKeys().finally(() => {
      this.keysRequest = undefined;
    });
    return this.keysRequest;
  }

  private async fetchKeys(): Promise<void> {
    const fetchImpl = this.options.fetch ?? fetch;
    const response = await fetchImpl(this.options.jwksUrl ?? GOOGLE_JWKS_URL, {
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok) throw new Error(`Google JWKS returned HTTP ${response.status}`);
    const document = (await response.json()) as JwksDocument;
    if (!Array.isArray(document.keys)) throw new Error("Google JWKS response has no keys");
    const next = new Map<string, JsonWebKey>();
    for (const key of document.keys) {
      if (typeof key.kid === "string" && key.kty === "RSA") next.set(key.kid, key);
    }
    if (next.size === 0) throw new Error("Google JWKS response has no RSA keys");
    const maxAge = parseMaxAge(response.headers.get("cache-control"));
    this.keys = next;
    this.keysExpireAt =
      (this.options.now?.() ?? new Date()).getTime() + (maxAge ?? DEFAULT_JWKS_TTL_MS);
  }
}

export function createMachineAuth(
  verifier: GoogleOidcVerifier,
  audit?: (event: MachineAuditEvent) => Promise<void>,
): RequestHandler {
  return async (req, res, next) => {
    const token = req.get("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
    if (!token) {
      res.status(401).json({ error: "OIDC bearer token required" });
      return;
    }
    let result: MachineVerification;
    try {
      result = await verifier.verify(token);
    } catch (error) {
      next(error);
      return;
    }
    if (!result.ok) {
      res.status(result.status).json({ error: result.reason });
      return;
    }
    req.machinePrincipal = result.principal;
    if (audit) {
      res.once("finish", () => {
        void audit({
          subject: result.principal,
          method: req.method,
          path: req.originalUrl,
          status: res.statusCode,
        }).catch((error) => log.error({ error }, "Failed to audit machine invocation"));
      });
    }
    next();
  };
}

export function loadMachineAuth(
  config: AppConfig,
  audit?: (event: MachineAuditEvent) => Promise<void>,
): RequestHandler {
  const audience = config.WALRUS_INTERNAL_AUDIENCE;
  const serviceAccount = config.WALRUS_INTERNAL_SERVICE_ACCOUNT;
  if (!audience || !serviceAccount) {
    if (config.NODE_ENV === "production") {
      throw new Error(
        "WALRUS_INTERNAL_AUDIENCE and WALRUS_INTERNAL_SERVICE_ACCOUNT are required in production",
      );
    }
    log.warn("Internal OIDC configuration is unset; /internal will fail closed");
    return (_req, res) => {
      res.status(503).json({ error: "Machine authentication unavailable" });
    };
  }
  return createMachineAuth(new GoogleOidcVerifier({ audience, serviceAccount }), audit);
}

function decodeJson<T>(value: string): T | undefined {
  try {
    return JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as T;
  } catch {
    return undefined;
  }
}

function decodeBase64Url(value: string): Buffer | undefined {
  try {
    return Buffer.from(value, "base64url");
  } catch {
    return undefined;
  }
}

function parseMaxAge(value: string | null): number | undefined {
  const seconds = value?.match(/(?:^|,)\s*max-age=(\d+)/i)?.[1];
  return seconds ? Number(seconds) * 1000 : undefined;
}

function unauthorized(reason: string): MachineVerification {
  return { ok: false, status: 401, reason };
}

function forbidden(reason: string): MachineVerification {
  return { ok: false, status: 403, reason };
}
