import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createAdminRoster } from "../../src/authn/admins.js";
import { installOperatorAuth, loginBackoffMs, SESSION_COOKIE } from "../../src/authn/operator.js";
import type { OperatorAuthRuntime } from "../../src/authn/runtime.js";
import { mintSession, verifySession } from "../../src/authn/session.js";

const now = new Date("2026-08-30T12:00:00.000Z");

function runtime(overrides: Partial<OperatorAuthRuntime> = {}): OperatorAuthRuntime {
  return {
    provider: {
      name: "fake",
      apiVersion: 1,
      authenticate: async ({ username, password }) =>
        password === "correct"
          ? { ok: true, subject: username }
          : { ok: false, reason: "invalid_credentials" },
    },
    roster: createAdminRoster(["admin"], "fold"),
    sessions: {
      currentKey: Buffer.from("01234567890123456789012345678901"),
      ttlSeconds: 7200,
      maxSeconds: 28_800,
      epoch: 1,
    },
    keyFingerprint: "12345678",
    nodeEnv: "development",
    now: () => now,
    minimumLoginMs: 0,
    ...overrides,
  };
}

function app(authRuntime: OperatorAuthRuntime) {
  const router = express.Router();
  installOperatorAuth(router, authRuntime);
  router.get("/", (req, res) => res.json({ subject: req.auth?.subject }));
  router.post("/change", (_req, res) => res.status(204).end());
  return express()
    .set("trust proxy", 1)
    .use(express.json())
    .use(express.urlencoded({ extended: false }))
    .use("/admin/v1", router);
}

describe("operator authentication", () => {
  it("renders login with the shared Walrus page chrome and signed-out state", async () => {
    const target = app(runtime());
    const login = await request(target).get("/admin/v1/login").expect(200);
    expect(login.text).toContain('name="viewport"');
    expect(login.text).toContain('class="brand" href="/">Walrus</a>');
    expect(login.text).toContain('class="panel"');
    expect(login.text).toContain('class="btn btn-primary"');

    const signedOut = await request(target).get("/admin/v1/login?logged_out=1").expect(200);
    expect(signedOut.text).toContain("You have been signed out.");
    expect(signedOut.text).toContain('role="status"');
  });

  it("uses an HttpOnly scoped cookie for form login", async () => {
    const response = await request(app(runtime()))
      .post("/admin/v1/login")
      .type("form")
      .send({ username: "admin", password: "correct", return_to: "/admin/v1/change" })
      .expect(303)
      .expect("location", "/admin/v1/change");

    const cookie = response.headers["set-cookie"]?.[0] as unknown as string;
    expect(cookie).toContain(`${SESSION_COOKIE}=`);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Lax");
    expect(cookie).toContain("Path=/admin/v1");
    expect(cookie).not.toContain("Secure");
  });

  it("marks the browser cookie Secure outside development", async () => {
    const response = await request(app(runtime({ nodeEnv: "production" })))
      .post("/admin/v1/login")
      .type("form")
      .send({ username: "admin", password: "correct" })
      .expect(303);
    expect(response.headers["set-cookie"]?.[0]).toContain("Secure");
  });

  it("returns a kind-bound bearer token for JSON login", async () => {
    const authRuntime = runtime();
    const response = await request(app(authRuntime))
      .post("/admin/v1/login")
      .send({ username: "admin", password: "correct" })
      .expect(200);

    await request(app(authRuntime))
      .get("/admin/v1/")
      .set("authorization", `Bearer ${response.body.token}`)
      .expect(200, { subject: "admin" });
    await request(app(authRuntime))
      .get("/admin/v1/")
      .set("cookie", `${SESSION_COOKIE}=${response.body.token}`)
      .expect(401);
  });

  it("rejects a cookie token used as bearer authentication", async () => {
    const authRuntime = runtime();
    const cookie = mintSession("admin", "cookie", authRuntime.sessions, now).token;
    await request(app(authRuntime))
      .get("/admin/v1/")
      .set("authorization", `Bearer ${cookie}`)
      .expect(401);
  });

  it("redirects unauthenticated HTML GETs but returns JSON 401 otherwise", async () => {
    const target = app(runtime());
    await request(target)
      .get("/admin/v1/")
      .set("accept", "text/html")
      .expect(303)
      .expect("location", "/admin/v1/login?return_to=%2Fadmin%2Fv1%2F");
    await request(target).get("/admin/v1/").expect(401);
    await request(target).post("/admin/v1/change").expect(401);
  });

  it("sends a lapsed browser form post to the login page instead of a JSON 401", async () => {
    const target = app(runtime());
    // What the admin nav's forms actually send once the session key has rotated under them.
    await request(target)
      .post("/admin/v1/tokens")
      .set("accept", "text/html")
      .type("form")
      .send({})
      .expect(303)
      .expect("location", "/admin/v1/login?expired=1");

    const loggedOut = await request(target)
      .post("/admin/v1/logout")
      .set("accept", "text/html")
      .type("form")
      .send({})
      .expect(303)
      .expect("location", "/admin/v1/login?logged_out=1");
    // Logging out is idempotent: the stale cookie goes even though no session was verified.
    expect(loggedOut.headers["set-cookie"].join()).toContain("walrus_session=;");

    // API clients are unaffected — no text/html, no form encoding.
    await request(target)
      .post("/admin/v1/logout")
      .expect(401)
      .expect({ error: "Authentication required" });
  });

  it("rechecks the administrator roster on every request", async () => {
    const authRuntime = runtime();
    const token = mintSession("removed-admin", "bearer", authRuntime.sessions, now).token;
    await request(app(authRuntime))
      .get("/admin/v1/")
      .set("authorization", `Bearer ${token}`)
      .expect(403);
  });

  it("rejects cross-origin writes and audits accepted writes with the subject", async () => {
    const auditAction = vi.fn(async () => undefined);
    const authRuntime = runtime({ auditAction });
    const token = mintSession("admin", "bearer", authRuntime.sessions, now).token;
    const target = app(authRuntime);

    await request(target)
      .post("/admin/v1/change")
      .set("authorization", `Bearer ${token}`)
      .set("origin", "https://attacker.example")
      .expect(403);
    await request(target)
      .post("/admin/v1/change")
      .set("authorization", `Bearer ${token}`)
      .expect(204);
    await vi.waitFor(() => expect(auditAction).toHaveBeenCalledTimes(1));
    expect(auditAction).toHaveBeenCalledWith(
      expect.objectContaining({ subject: "admin", kind: "bearer", status: 204 }),
    );
  });

  it("requires a matching Origin for cookie-authenticated writes", async () => {
    const authRuntime = runtime();
    const cookie = mintSession("admin", "cookie", authRuntime.sessions, now).token;
    const target = app(authRuntime);

    await request(target)
      .post("/admin/v1/change")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .expect(403, { error: "Origin header required for browser admin request" });
    await request(target)
      .post("/admin/v1/change")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .set("host", "walrus.test")
      .set("origin", "http://attacker.test")
      .expect(403, { error: "Cross-origin admin request rejected" });
    await request(target)
      .post("/admin/v1/change")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .set("host", "walrus.test")
      .set("origin", "http://walrus.test")
      .expect(204);
  });

  it("clears the scoped cookie on logout and documents stateless bearer behavior", async () => {
    const authRuntime = runtime();
    const cookie = mintSession("admin", "cookie", authRuntime.sessions, now).token;
    const response = await request(app(authRuntime))
      .post("/admin/v1/logout")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .set("host", "walrus.test")
      .set("origin", "http://walrus.test")
      .expect(200);
    expect(response.body.message).toContain("stateless tokens are not revoked");
    expect(response.headers["set-cookie"]?.[0]).toContain(`${SESSION_COOKIE}=;`);
    expect(response.headers["set-cookie"]?.[0]).toContain("Path=/admin/v1");

    await request(app(authRuntime))
      .post("/admin/v1/logout")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .set("host", "walrus.test")
      .set("origin", "http://walrus.test")
      .set("accept", "text/html")
      .expect(303)
      .expect("location", "/admin/v1/login?logged_out=1");
  });

  it("distinguishes provider unavailability in response and audit", async () => {
    const auditLogin = vi.fn(async () => undefined);
    const authRuntime = runtime({
      auditLogin,
      provider: {
        name: "directory",
        apiVersion: 1,
        authenticate: async () => ({ ok: false, reason: "unavailable" }),
      },
    });
    await request(app(authRuntime))
      .post("/admin/v1/login")
      .send({ username: "admin", password: "correct" })
      .expect(503);
    expect(auditLogin).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: "unavailable", provider: "directory" }),
    );
  });

  it("audits a thrown provider failure as unavailable without exposing its error", async () => {
    const auditLogin = vi.fn(async () => undefined);
    const authRuntime = runtime({
      auditLogin,
      provider: {
        name: "directory",
        apiVersion: 1,
        authenticate: async () => Promise.reject(new Error("bind credentials leaked here")),
      },
    });
    const response = await request(app(authRuntime))
      .post("/admin/v1/login")
      .send({ username: "admin", password: "correct" })
      .expect(503);
    expect(response.text).not.toContain("bind credentials leaked here");
    expect(auditLogin).toHaveBeenCalledWith(
      expect.objectContaining({ outcome: "unavailable", provider: "directory" }),
    );
  });

  it("renews only cookie sessions after half their TTL and preserves the absolute cap", async () => {
    const initialRuntime = runtime();
    const initial = mintSession("admin", "cookie", initialRuntime.sessions, now);
    const later = new Date(now.getTime() + 60 * 60 * 1000 + 1000);
    const response = await request(app(runtime({ now: () => later })))
      .get("/admin/v1/whoami")
      .set("cookie", `${SESSION_COOKIE}=${initial.token}`)
      .expect(200);
    const renewedCookie = response.headers["set-cookie"]?.[0] as unknown as string;
    const renewedToken = renewedCookie.match(new RegExp(`${SESSION_COOKIE}=([^;]+)`))?.[1];
    expect(renewedToken).toBeTruthy();
    const verified = verifySession(renewedToken!, initialRuntime.sessions, {
      now: later,
      expectedKind: "cookie",
    });
    expect(verified).toMatchObject({ ok: true });
    if (verified.ok) expect(verified.payload.cap).toBe(initial.payload.cap);

    const bearer = mintSession("admin", "bearer", initialRuntime.sessions, now).token;
    const bearerResponse = await request(app(runtime({ now: () => later })))
      .get("/admin/v1/whoami")
      .set("authorization", `Bearer ${bearer}`)
      .expect(200);
    expect(bearerResponse.headers["set-cookie"]).toBeUndefined();
  });

  it("mints a fresh bearer without exposing the browser cookie token", async () => {
    const authRuntime = runtime();
    const cookie = mintSession("admin", "cookie", authRuntime.sessions, now).token;
    const response = await request(app(authRuntime))
      .post("/admin/v1/tokens")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .set("host", "walrus.test")
      .set("origin", "http://walrus.test")
      .expect(200);
    expect(response.body.token).not.toBe(cookie);
    expect(
      verifySession(response.body.token, authRuntime.sessions, {
        now,
        expectedKind: "bearer",
      }),
    ).toMatchObject({ ok: true });
  });

  it("offers browser admins a one-time styled API-token page", async () => {
    const authRuntime = runtime();
    const cookie = mintSession("admin", "cookie", authRuntime.sessions, now).token;
    const response = await request(app(authRuntime))
      .post("/admin/v1/tokens")
      .set("cookie", `${SESSION_COOKIE}=${cookie}`)
      .set("host", "walrus.test")
      .set("origin", "http://walrus.test")
      .set("accept", "text/html")
      .expect(200)
      .expect("content-type", /html/);
    expect(response.text).toContain("New API token");
    expect(response.text).toContain("displayed once");
    expect(response.text).toContain('action="/admin/v1/logout"');
    expect(response.text).toContain('href="/admin/v1/">Return to admin</a>');
    expect(response.text).not.toContain(cookie);
    const bearer = response.text.match(/<textarea[^>]*>([^<]+)<\/textarea>/)?.[1];
    expect(bearer).toBeTruthy();
    expect(
      verifySession(bearer!, authRuntime.sessions, { now, expectedKind: "bearer" }),
    ).toMatchObject({ ok: true });
  });

  it("uses bounded exponential login backoff", () => {
    expect([1, 2, 3, 8, 100].map(loginBackoffMs)).toEqual([250, 500, 1000, 30_000, 30_000]);
  });

  it.each([
    ["successful", "correct", 200],
    ["unsuccessful", "wrong", 401],
  ] as const)(
    "enforces the response-time floor for a %s login",
    async (_label, password, status) => {
      let clock = 10_000;
      const sleeps: number[] = [];
      const authRuntime = runtime({
        minimumLoginMs: 250,
        loginTiming: {
          now: () => clock,
          sleep: async (milliseconds) => {
            sleeps.push(milliseconds);
            clock += milliseconds;
          },
        },
      });
      await request(app(authRuntime))
        .post("/admin/v1/login")
        .send({ username: "admin", password })
        .expect(status);
      expect(sleeps.filter((milliseconds) => milliseconds > 0)).toEqual([250]);
    },
  );

  it.each([
    ["IP address", "alice", "bob", "203.0.113.7", "203.0.113.7"],
    ["username", "alice", "alice", "203.0.113.7", "203.0.113.8"],
  ] as const)(
    "throttles independently by %s",
    async (_label, firstUser, secondUser, firstIp, secondIp) => {
      let clock = 20_000;
      const sleeps: number[] = [];
      const authRuntime = runtime({
        provider: {
          name: "fake",
          apiVersion: 1,
          authenticate: async ({ password }) =>
            password === "correct"
              ? { ok: true, subject: "admin" }
              : { ok: false, reason: "invalid_credentials" },
        },
        loginTiming: {
          now: () => clock,
          sleep: async (milliseconds) => {
            sleeps.push(milliseconds);
            clock += milliseconds;
          },
        },
      });
      const target = app(authRuntime);
      await request(target)
        .post("/admin/v1/login")
        .set("x-forwarded-for", firstIp)
        .send({ username: firstUser, password: "wrong" })
        .expect(401);
      await request(target)
        .post("/admin/v1/login")
        .set("x-forwarded-for", secondIp)
        .send({ username: secondUser, password: "correct" })
        .expect(200);
      expect(sleeps.filter((milliseconds) => milliseconds > 0)).toEqual([250]);
    },
  );

  it("does not allow an external return URL", async () => {
    await request(app(runtime()))
      .post("/admin/v1/login")
      .type("form")
      .send({ username: "admin", password: "correct", return_to: "https://attacker.example" })
      .expect(303)
      .expect("location", "/admin/v1/");
  });
});
