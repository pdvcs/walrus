import { generateKeyPairSync, sign } from "node:crypto";
import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import {
  createMachineAuth,
  GoogleOidcVerifier,
  loadMachineAuth,
} from "../../src/authn/google-oidc.js";
import type { AppConfig } from "../../src/config/index.js";

const now = new Date("2026-08-30T12:00:00.000Z");
const audience = "https://walrus.example/internal";
const serviceAccount = "scheduler@example.iam.gserviceaccount.com";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256" };

function token(
  claims: Partial<Record<string, unknown>> = {},
  header: Record<string, unknown> = { alg: "RS256", kid: "test-key" },
): string {
  const seconds = Math.floor(now.getTime() / 1000);
  const encodedHeader = Buffer.from(JSON.stringify(header)).toString("base64url");
  const encodedClaims = Buffer.from(
    JSON.stringify({
      iss: "https://accounts.google.com",
      aud: audience,
      exp: seconds + 300,
      iat: seconds,
      email: serviceAccount,
      email_verified: true,
      ...claims,
    }),
  ).toString("base64url");
  const signature = sign(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedClaims}`),
    privateKey,
  ).toString("base64url");
  return `${encodedHeader}.${encodedClaims}.${signature}`;
}

function verifier() {
  const fetchMock = vi.fn(
    async () =>
      new Response(JSON.stringify({ keys: [jwk] }), {
        status: 200,
        headers: { "cache-control": "public, max-age=3600" },
      }),
  );
  return {
    fetchMock,
    verifier: new GoogleOidcVerifier({
      audience,
      serviceAccount,
      now: () => now,
      fetch: fetchMock,
    }),
  };
}

function jwksResponse(
  body: unknown = { keys: [jwk] },
  options: { status?: number; maxAge?: number } = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: options.status ?? 200,
    headers: { "cache-control": `public, max-age=${options.maxAge ?? 3600}` },
  });
}

describe("GoogleOidcVerifier", () => {
  it("verifies Google signature, audience, expiry, and scheduler principal", async () => {
    const instance = verifier();
    await expect(instance.verifier.verify(token())).resolves.toMatchObject({
      ok: true,
      principal: serviceAccount,
    });
    await expect(instance.verifier.verify(token())).resolves.toMatchObject({ ok: true });
    expect(instance.fetchMock).toHaveBeenCalledTimes(1);
  });

  it.each([
    ["wrong audience", { aud: "https://other.example" }, 403],
    ["wrong principal", { email: "other@example.iam.gserviceaccount.com" }, 403],
    ["expired token", { exp: Math.floor(now.getTime() / 1000) - 1 }, 401],
  ])("rejects a %s", async (_label, claims, status) => {
    const instance = verifier();
    await expect(instance.verifier.verify(token(claims))).resolves.toMatchObject({
      ok: false,
      status,
    });
  });

  it("rejects a tampered signature", async () => {
    const instance = verifier();
    const signed = token();
    await expect(instance.verifier.verify(`${signed.slice(0, -2)}aa`)).resolves.toMatchObject({
      ok: false,
      status: 401,
    });
  });

  it.each([
    ["wrong algorithm", token({}, { alg: "HS256", kid: "test-key" }), 401],
    ["wrong issuer", token({ iss: "https://issuer.example" }), 401],
    ["future issue time", token({ iat: Math.floor(now.getTime() / 1000) + 61 }), 401],
    ["unverified email", token({ email_verified: false }), 403],
    ["missing email verification", token({ email_verified: undefined }), 403],
    ["unknown signing key", token({}, { alg: "RS256", kid: "unknown" }), 401],
  ])("rejects %s", async (_label, value, status) => {
    const instance = verifier();
    await expect(instance.verifier.verify(value)).resolves.toMatchObject({ ok: false, status });
  });

  it("rejects malformed and oversized tokens without fetching keys", async () => {
    const instance = verifier();
    await expect(instance.verifier.verify("not-a-jwt")).resolves.toMatchObject({
      ok: false,
      status: 401,
    });
    await expect(instance.verifier.verify("x".repeat(16_385))).resolves.toMatchObject({
      ok: false,
      status: 401,
    });
    expect(instance.fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["HTTP failure", async () => jwksResponse({}, { status: 500 })],
    ["malformed JSON", async () => new Response("{", { status: 200 })],
    ["missing keys", async () => jwksResponse({})],
    ["no RSA keys", async () => jwksResponse({ keys: [{ kid: "test-key", kty: "EC" }] })],
  ])("fails closed when JWKS has an %s", async (_label, fetchImpl) => {
    const instance = new GoogleOidcVerifier({
      audience,
      serviceAccount,
      now: () => now,
      fetch: fetchImpl,
    });
    await expect(instance.verify(token())).resolves.toMatchObject({
      ok: false,
      status: 401,
      reason: "OIDC signing keys unavailable",
    });
  });

  it("refreshes the JWKS cache only after max-age expires", async () => {
    let current = now;
    const fetchMock = vi.fn(async () => jwksResponse({ keys: [jwk] }, { maxAge: 1 }));
    const instance = new GoogleOidcVerifier({
      audience,
      serviceAccount,
      now: () => current,
      fetch: fetchMock,
    });
    await expect(instance.verify(token())).resolves.toMatchObject({ ok: true });
    current = new Date(now.getTime() + 999);
    await expect(instance.verify(token())).resolves.toMatchObject({ ok: true });
    current = new Date(now.getTime() + 1000);
    await expect(instance.verify(token())).resolves.toMatchObject({ ok: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("shares one in-flight JWKS request across concurrent verification", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchMock = vi.fn(async () => {
      await gate;
      return jwksResponse();
    });
    const instance = new GoogleOidcVerifier({
      audience,
      serviceAccount,
      now: () => now,
      fetch: fetchMock,
    });
    const first = instance.verify(token());
    const second = instance.verify(token());
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
    release();
    await expect(Promise.all([first, second])).resolves.toEqual([
      expect.objectContaining({ ok: true }),
      expect.objectContaining({ ok: true }),
    ]);
  });

  it("rate-limits refreshes caused by unknown key IDs", async () => {
    const fetchMock = vi.fn(async () => jwksResponse());
    const instance = new GoogleOidcVerifier({
      audience,
      serviceAccount,
      now: () => now,
      fetch: fetchMock,
    });
    await instance.verify(token());
    await expect(
      instance.verify(token({}, { alg: "RS256", kid: "unknown-one" })),
    ).resolves.toMatchObject({ ok: false, status: 401 });
    await expect(
      instance.verify(token({}, { alg: "RS256", kid: "unknown-two" })),
    ).resolves.toMatchObject({ ok: false, status: 401 });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});

describe("createMachineAuth", () => {
  it("fails closed and records the verified machine subject", async () => {
    const instance = verifier();
    const audit = vi.fn(async () => undefined);
    const app = express().use(
      "/internal",
      createMachineAuth(instance.verifier, audit),
      (req, res) => res.json({ principal: req.machinePrincipal }),
    );

    await request(app).get("/internal/sync").expect(401);
    await request(app)
      .post("/internal/sync")
      .set("authorization", `Bearer ${token()}`)
      .expect(200, { principal: serviceAccount });
    await vi.waitFor(() => expect(audit).toHaveBeenCalledTimes(1));
    expect(audit).toHaveBeenCalledWith(
      expect.objectContaining({ subject: serviceAccount, path: "/internal/sync", status: 200 }),
    );
  });

  it("fails production boot when audience or scheduler principal is missing", () => {
    expect(() => loadMachineAuth({ NODE_ENV: "production" } as AppConfig)).toThrow(
      "required in production",
    );
  });

  it("passes unexpected verifier failures to Express error handling", async () => {
    const brokenVerifier = {
      verify: async () => Promise.reject(new Error("verification crashed")),
    } as unknown as GoogleOidcVerifier;
    const app = express()
      .use(createMachineAuth(brokenVerifier))
      .use(
        (error: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) =>
          res.status(500).json({ error: error.message }),
      );
    await request(app)
      .get("/")
      .set("authorization", "Bearer token")
      .expect(500, { error: "verification crashed" });
  });
});
