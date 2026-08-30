import type { z } from "zod";

export interface Credentials {
  username: string;
  password: string;
}

export type AuthnResult =
  | { ok: true; subject: string; displayName?: string }
  | { ok: false; reason: "invalid_credentials" | "unavailable"; detail?: string };

export interface AuthnProvider {
  readonly name: string;
  readonly apiVersion: 1;
  readonly configSchema?: z.ZodType;
  init?(config: unknown): Promise<void>;
  authenticate(credentials: Credentials): Promise<AuthnResult>;
}
