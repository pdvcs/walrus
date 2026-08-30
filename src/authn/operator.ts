import type { Request, RequestHandler, Response, Router } from "express";
import { log } from "../common/log.js";
import { mintSession, renewSession, verifySession, type SessionPayload } from "./session.js";
import type { OperatorAuthRuntime } from "./runtime.js";
import type { AuthnResult } from "./types.js";
import { escapeHtml, renderAdminNav, renderPage, renderPublicNav } from "../routes/page-shell.js";

export const SESSION_COOKIE = "walrus_session";

interface LoginFailureState {
  failures: number;
  retryAt: number;
}

export function installOperatorAuth(router: Router, runtime: OperatorAuthRuntime): void {
  const failures = new Map<string, LoginFailureState>();
  const timing = runtime.loginTiming ?? { now: Date.now, sleep: delay };

  router.get("/login", (req, res) => {
    const notice = req.query.logged_out === "1" ? "You have been signed out." : undefined;
    res
      .type("html")
      .send(renderLoginPage(safeReturnPath(stringValue(req.query.return_to)), undefined, notice));
  });

  router.post("/login", async (req, res, next) => {
    const started = timing.now();
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const username = stringValue(body.username)?.trim() ?? "";
      const password = stringValue(body.password) ?? "";
      const ip = req.ip || req.socket.remoteAddress || "unknown";
      const throttleKeys = [`username:${username.normalize("NFKC").toLowerCase()}`, `ip:${ip}`];
      await waitForThrottle(
        throttleKeys.map((key) => failures.get(key)),
        timing,
      );

      let result: AuthnResult;
      try {
        result = await runtime.provider.authenticate({ username, password });
      } catch (error) {
        log.error({ error, provider: runtime.provider.name }, "Authentication provider failed");
        await runtime.auditLogin?.({
          outcome: "unavailable",
          username,
          provider: runtime.provider.name,
          ip,
        });
        await enforceFloor(started, runtime.minimumLoginMs ?? 250, timing);
        sendLoginFailure(req, res, 503, "Authentication provider unavailable");
        return;
      }
      if (!result.ok) {
        if (result.reason === "invalid_credentials") {
          recordFailures(failures, throttleKeys, timing.now());
          await runtime.auditLogin?.({
            outcome: "invalid_credentials",
            username,
            provider: runtime.provider.name,
            ip,
          });
          await enforceFloor(started, runtime.minimumLoginMs ?? 250, timing);
          sendLoginFailure(req, res, 401, "Invalid username or password");
          return;
        }
        await runtime.auditLogin?.({
          outcome: "unavailable",
          username,
          provider: runtime.provider.name,
          ip,
        });
        await enforceFloor(started, runtime.minimumLoginMs ?? 250, timing);
        sendLoginFailure(req, res, 503, "Authentication provider unavailable");
        return;
      }

      if (!runtime.roster.has(result.subject)) {
        recordFailures(failures, throttleKeys, timing.now());
        await runtime.auditLogin?.({
          outcome: "forbidden",
          username,
          provider: runtime.provider.name,
          ip,
          subject: result.subject,
        });
        await enforceFloor(started, runtime.minimumLoginMs ?? 250, timing);
        sendLoginFailure(req, res, 403, "Authenticated subject is not an administrator");
        return;
      }

      for (const key of throttleKeys) failures.delete(key);
      await runtime.auditLogin?.({
        outcome: "success",
        username,
        provider: runtime.provider.name,
        ip,
        subject: result.subject,
      });
      await enforceFloor(started, runtime.minimumLoginMs ?? 250, timing);
      const now = runtime.now?.() ?? new Date();
      if (isFormRequest(req)) {
        const session = mintSession(result.subject, "cookie", runtime.sessions, now);
        setSessionCookie(res, session.token, session.payload, runtime);
        res.redirect(303, safeReturnPath(stringValue(body.return_to)) ?? "/admin/v1/");
        return;
      }

      const session = mintSession(result.subject, "bearer", runtime.sessions, now);
      res.json({
        token: session.token,
        expires_at: new Date(session.payload.exp * 1000).toISOString(),
        subject: session.payload.sub,
      });
    } catch (error) {
      next(error);
    }
  });

  router.use(createOperatorGuard(runtime));
  router.use(createOriginGuard());
  router.use(createOperatorAudit(runtime));

  router.post("/logout", (_req, res) => {
    clearSessionCookie(res, runtime);
    if (res.req.headers.accept?.includes("text/html")) {
      res.redirect(303, "/admin/v1/login?logged_out=1");
      return;
    }
    res.json({ logged_out: true, message: "Cookie cleared; stateless tokens are not revoked" });
  });

  router.get("/whoami", (req, res) => {
    const auth = req.auth!;
    res.json({
      subject: auth.subject,
      kind: auth.kind,
      expires_at: new Date(auth.payload.exp * 1000).toISOString(),
      absolute_expires_at: new Date(auth.payload.cap * 1000).toISOString(),
      provider: runtime.provider.name,
      session_key_fingerprint: runtime.keyFingerprint,
    });
  });

  router.post("/tokens", (req, res) => {
    const session = mintSession(
      req.auth!.subject,
      "bearer",
      runtime.sessions,
      runtime.now?.() ?? new Date(),
    );
    if (req.headers.accept?.includes("text/html")) {
      res.type("html").send(renderBearerTokenPage(session.token, session.payload));
      return;
    }
    res.json({
      token: session.token,
      expires_at: new Date(session.payload.exp * 1000).toISOString(),
      subject: session.payload.sub,
    });
  });
}

export function createOperatorGuard(runtime: OperatorAuthRuntime): RequestHandler {
  return (req, res, next) => {
    const authorization = req.get("authorization");
    const bearer = authorization?.match(/^Bearer\s+(.+)$/i)?.[1];
    const cookie = parseCookies(req.get("cookie"))[SESSION_COOKIE];
    const token = bearer ?? cookie;
    const expectedKind = bearer ? "bearer" : "cookie";
    if (!token) {
      sendUnauthenticated(req, res);
      return;
    }

    const verified = verifySession(token, runtime.sessions, {
      now: runtime.now?.() ?? new Date(),
      expectedKind,
    });
    if (!verified.ok) {
      sendUnauthenticated(req, res);
      return;
    }
    if (!runtime.roster.has(verified.payload.sub)) {
      res.status(403).json({ error: "Authenticated subject is not an administrator" });
      return;
    }

    req.auth = {
      subject: verified.payload.sub,
      kind: verified.payload.k,
      payload: verified.payload,
    };
    if (verified.payload.k === "cookie") {
      const renewed = renewSession(
        verified.payload,
        runtime.sessions,
        runtime.now?.() ?? new Date(),
      );
      if (renewed) {
        req.auth.payload = renewed.payload;
        setSessionCookie(res, renewed.token, renewed.payload, runtime);
      }
    }
    next();
  };
}

function createOriginGuard(): RequestHandler {
  return (req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") return next();
    const origin = req.get("origin");
    if (!origin && req.auth?.kind === "cookie") {
      res.status(403).json({ error: "Origin header required for browser admin request" });
      return;
    }
    if (!origin) return next();
    const expected = `${req.protocol}://${req.get("host")}`;
    if (origin !== expected) {
      res.status(403).json({ error: "Cross-origin admin request rejected" });
      return;
    }
    next();
  };
}

function createOperatorAudit(runtime: OperatorAuthRuntime): RequestHandler {
  return (req, res, next) => {
    if (!runtime.auditAction || ["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
    res.once("finish", () => {
      const auth = req.auth;
      if (!auth) return;
      void runtime.auditAction!({
        subject: auth.subject,
        kind: auth.kind,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
      }).catch((error) => log.error({ error }, "Failed to audit operator action"));
    });
    next();
  };
}

function sendUnauthenticated(req: Request, res: Response): void {
  if (req.method === "GET" && req.headers.accept?.includes("text/html")) {
    const returnTo = safeReturnPath(req.originalUrl);
    const query = returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : "";
    res.redirect(303, `/admin/v1/login${query}`);
    return;
  }
  res.status(401).json({ error: "Authentication required" });
}

function sendLoginFailure(req: Request, res: Response, status: number, message: string): void {
  if (isFormRequest(req) || req.headers.accept?.includes("text/html")) {
    res.status(status).type("html").send(renderLoginPage(undefined, message));
    return;
  }
  res.status(status).json({ error: message });
}

function setSessionCookie(
  res: Response,
  token: string,
  payload: SessionPayload,
  runtime: OperatorAuthRuntime,
): void {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: runtime.nodeEnv !== "development",
    sameSite: "lax",
    path: "/admin/v1",
    expires: new Date(payload.exp * 1000),
  });
}

function clearSessionCookie(res: Response, runtime: OperatorAuthRuntime): void {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: runtime.nodeEnv !== "development",
    sameSite: "lax",
    path: "/admin/v1",
  });
}

function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of header?.split(";") ?? []) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    try {
      cookies[name] = decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      // A malformed unrelated cookie must not make the whole request a 500.
    }
  }
  return cookies;
}

export function safeReturnPath(value: string | undefined): string | undefined {
  if (!value || !value.startsWith("/admin/v1/")) return undefined;
  if (value.startsWith("//") || value.includes("\\")) return undefined;
  return value;
}

function renderLoginPage(returnTo?: string, error?: string, notice?: string): string {
  return renderPage({
    title: "Operator login — Walrus",
    nav: renderPublicNav(),
    body: `<section class="panel">
      <h1>Operator login</h1>
      <p class="meta">Sign in with the administrator credentials configured for this Walrus instance.</p>
      ${error ? `<p class="alert alert-error" role="alert">${escapeHtml(error)}</p>` : ""}
      ${notice ? `<p class="alert alert-success" role="status">${escapeHtml(notice)}</p>` : ""}
      <form method="post" action="/admin/v1/login">
        <div class="field"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus></div>
        <div class="field"><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required></div>
        ${returnTo ? `<input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">` : ""}
        <div class="actions"><button class="btn btn-primary" type="submit">Sign in</button><a class="btn btn-secondary" href="/">Back to Walrus</a></div>
      </form>
    </section>`,
  });
}

function renderBearerTokenPage(token: string, payload: SessionPayload): string {
  const expiresAt = escapeHtml(new Date(payload.exp * 1000).toISOString());
  return renderPage({
    title: "New API token — Walrus Admin",
    nav: renderAdminNav(),
    body: `<section class="panel">
      <h1>New API token</h1>
      <p>This bearer credential is displayed once. It expires at <strong>${expiresAt}</strong>.</p>
      <p class="alert alert-error" role="alert">Treat this token as a password. It cannot be revoked individually and will not be shown again.</p>
      <div class="field"><label for="api-token">Bearer token</label><textarea id="api-token" readonly rows="7" spellcheck="false">${escapeHtml(token)}</textarea></div>
      <div class="actions"><a class="btn btn-primary" href="/admin/v1/">Return to admin</a><a class="btn btn-secondary" href="/api">API documentation</a></div>
    </section>`,
  });
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isFormRequest(req: Request): boolean {
  return Boolean(req.is("application/x-www-form-urlencoded"));
}

function recordFailures(
  failures: Map<string, LoginFailureState>,
  keys: readonly string[],
  now: number,
): void {
  for (const key of keys) {
    const count = (failures.get(key)?.failures ?? 0) + 1;
    const delayMs = loginBackoffMs(count);
    failures.set(key, { failures: count, retryAt: now + delayMs });
  }
}

export function loginBackoffMs(failureCount: number): number {
  return Math.min(30_000, 250 * 2 ** Math.min(Math.max(failureCount - 1, 0), 7));
}

async function waitForThrottle(
  states: Array<LoginFailureState | undefined>,
  timing: { now: () => number; sleep: (milliseconds: number) => Promise<void> },
): Promise<void> {
  const retryAt = Math.max(0, ...states.map((state) => state?.retryAt ?? 0));
  await timing.sleep(Math.max(0, retryAt - timing.now()));
}

async function enforceFloor(
  started: number,
  floorMs: number,
  timing: { now: () => number; sleep: (milliseconds: number) => Promise<void> },
): Promise<void> {
  await timing.sleep(Math.max(0, floorMs - (timing.now() - started)));
}

async function delay(milliseconds: number): Promise<void> {
  if (milliseconds <= 0) return;
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
}
