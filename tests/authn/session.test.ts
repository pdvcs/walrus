import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  mintSession,
  renewSession,
  SessionConfig,
  sessionKeyFingerprint,
  verifySession,
} from "../../src/authn/session.js";

const CURRENT = Buffer.alloc(32, "c");
const PREVIOUS = Buffer.alloc(32, "p");
const START = new Date("2026-08-30T10:00:00.000Z");

function config(overrides: Partial<SessionConfig> = {}): SessionConfig {
  return {
    currentKey: CURRENT,
    ttlSeconds: 120,
    maxSeconds: 480,
    epoch: 3,
    ...overrides,
  };
}

function at(seconds: number): Date {
  return new Date(START.getTime() + seconds * 1000);
}

function signRaw(payload: Record<string, unknown>, key = CURRENT): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", key).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

describe("stateless sessions", () => {
  it("round trips cookie and bearer payloads with their distinct expiry", () => {
    const cookie = mintSession("Admin@example.com", "cookie", config(), START);
    const bearer = mintSession("Admin@example.com", "bearer", config(), START);

    expect(verifySession(cookie.token, config(), { now: START, expectedKind: "cookie" })).toEqual({
      ok: true,
      payload: cookie.payload,
      signedWith: "current",
    });
    expect(cookie.payload.exp - cookie.payload.iat).toBe(120);
    expect(bearer.payload.exp).toBe(bearer.payload.cap);
  });

  it("rejects tampered payloads, signatures, wrong keys, kinds, and epochs", () => {
    const { token } = mintSession("admin", "cookie", config(), START);
    const [payload, signature] = token.split(".");
    const decoded = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    decoded.sub = "attacker";
    const tamperedPayload = Buffer.from(JSON.stringify(decoded)).toString("base64url");

    expect(
      verifySession(`${tamperedPayload}.${signature}`, config(), { now: START }),
    ).toMatchObject({
      ok: false,
      reason: "invalid_signature",
    });
    expect(
      verifySession(`${payload}.${signature.slice(0, -1)}x`, config(), { now: START }).ok,
    ).toBe(false);
    expect(
      verifySession(token, config({ currentKey: Buffer.alloc(32, "x") }), { now: START }).ok,
    ).toBe(false);
    expect(verifySession(token, config(), { now: START, expectedKind: "bearer" })).toMatchObject({
      ok: false,
      reason: "wrong_kind",
    });
    expect(verifySession(token, config({ epoch: 4 }), { now: START })).toMatchObject({
      ok: false,
      reason: "wrong_epoch",
    });
  });

  it("rejects an unsupported format version even when its signature is valid", () => {
    const payload = mintSession("admin", "cookie", config(), START).payload;
    expect(verifySession(signRaw({ ...payload, v: 2 }), config(), { now: START })).toEqual({
      ok: false,
      reason: "invalid_payload",
    });
  });

  it("accepts a previous key for verification but always signs with the current key", () => {
    const old = mintSession("admin", "cookie", config({ currentKey: PREVIOUS }), START);
    const rotated = config({ previousKey: PREVIOUS });
    expect(verifySession(old.token, rotated, { now: START })).toMatchObject({
      ok: true,
      signedWith: "previous",
    });

    const fresh = mintSession("admin", "cookie", rotated, START);
    expect(verifySession(fresh.token, config({ currentKey: PREVIOUS }), { now: START }).ok).toBe(
      false,
    );
  });

  it("enforces expiry, absolute cap, and future-issued clock skew", () => {
    const token = mintSession("admin", "cookie", config(), START).token;
    expect(verifySession(token, config(), { now: at(120) })).toMatchObject({
      ok: false,
      reason: "expired",
    });

    const future = mintSession("admin", "cookie", config(), at(60)).token;
    expect(verifySession(future, config(), { now: START }).ok).toBe(true);
    const tooFarFuture = mintSession("admin", "cookie", config(), at(61)).token;
    expect(verifySession(tooFarFuture, config(), { now: START })).toMatchObject({
      ok: false,
      reason: "future_issued",
    });
  });

  it("renews cookie sessions only after half TTL and preserves the absolute clocks", () => {
    const original = mintSession("admin", "cookie", config(), START);
    expect(renewSession(original.payload, config(), at(59))).toBeNull();
    const renewed = renewSession(original.payload, config(), at(60));
    expect(renewed).not.toBeNull();
    expect(renewed!.payload).toMatchObject({
      sub: original.payload.sub,
      iat: original.payload.iat,
      cap: original.payload.cap,
      exp: original.payload.iat + 180,
    });
    expect(
      renewSession(mintSession("admin", "bearer", config(), START).payload, config(), at(60)),
    ).toBeNull();
  });

  it("clamps renewal to cap and dies there regardless of repeated renewal", () => {
    let payload = mintSession("admin", "cookie", config(), START).payload;
    for (const seconds of [60, 120, 180, 240, 300, 360, 420]) {
      const renewed = renewSession(payload, config(), at(seconds));
      expect(renewed).not.toBeNull();
      payload = renewed!.payload;
      expect(payload.cap).toBe(Math.floor(START.getTime() / 1000) + 480);
    }
    expect(payload.exp).toBe(payload.cap);
    expect(renewSession(payload, config(), at(480))).toBeNull();
  });

  it("publishes a stable short fingerprint without revealing the key", () => {
    expect(sessionKeyFingerprint(CURRENT)).toMatch(/^[0-9a-f]{8}$/);
    expect(sessionKeyFingerprint(CURRENT)).not.toContain(CURRENT.toString("utf8"));
  });

  it("rejects unsafe key and lifetime configuration", () => {
    expect(() => mintSession("admin", "cookie", config({ currentKey: Buffer.alloc(31) }))).toThrow(
      "at least 32 bytes",
    );
    expect(() => mintSession("admin", "cookie", config({ maxSeconds: 60 }))).toThrow(
      "at least as large",
    );
  });
});
