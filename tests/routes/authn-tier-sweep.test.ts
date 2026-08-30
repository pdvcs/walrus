import type express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp, SECURITY_TIER_MOUNTS, type SecurityTierMount } from "../../src/main.js";
import { testOperatorAuth } from "../helpers/authn.js";

interface ExpressLayer {
  route?: { path: string | string[]; methods: Record<string, boolean> };
  handle?: { stack?: ExpressLayer[] };
  regexp?: RegExp;
}

interface DiscoveredRoute {
  method: "get" | "post" | "put" | "patch" | "delete";
  path: string;
}

function discoverRoutes(router: express.Router): DiscoveredRoute[] {
  const found: DiscoveredRoute[] = [];
  const walk = (layers: ExpressLayer[]): void => {
    for (const layer of layers) {
      if (layer.route) {
        const paths = Array.isArray(layer.route.path) ? layer.route.path : [layer.route.path];
        for (const path of paths) {
          for (const method of Object.keys(layer.route.methods)) {
            if (["get", "post", "put", "patch", "delete"].includes(method)) {
              found.push({ method: method as DiscoveredRoute["method"], path });
            }
          }
        }
      } else if (layer.handle?.stack) {
        walk(layer.handle.stack);
      }
    }
  };
  walk((router as unknown as { stack: ExpressLayer[] }).stack);
  return found;
}

function requestPath(prefix: string, routePath: string): string {
  const concrete = routePath.replace(/:([A-Za-z0-9_]+)/g, "test");
  return prefix === "/" ? concrete : `${prefix}${concrete === "/" ? "/" : concrete}`;
}

describe("application security tier mounts", () => {
  const auth = testOperatorAuth();
  const app = createApp({
    operatorAuth: auth.runtime,
    internalAuth: (_req, res) => res.status(401).json({ error: "OIDC bearer token required" }),
    health: { checkDatabase: async () => undefined },
  });

  const mounts = app.locals.securityTierMounts as SecurityTierMount[];

  it("uses the complete declared tier inventory exactly once", () => {
    expect(mounts.map(({ tier, prefix }) => ({ tier, prefix }))).toEqual(SECURITY_TIER_MOUNTS);
    expect(new Set(mounts.map(({ prefix }) => prefix)).size).toBe(mounts.length);
    expect(mounts.every(({ router }) => discoverRoutes(router).length > 0)).toBe(true);

    const applicationLayers = (app as unknown as { _router: { stack: ExpressLayer[] } })._router
      .stack;
    expect(applicationLayers.filter(({ route }) => route)).toHaveLength(0);
    const routeBearingRouters = applicationLayers.filter(
      ({ handle }) => handle?.stack && discoverRoutes(handle as express.Router).length > 0,
    );
    expect(routeBearingRouters.map(({ handle }) => handle)).toEqual(
      mounts.map(({ router }) => router),
    );
    for (const mount of mounts) {
      const layer = routeBearingRouters.find(({ handle }) => handle === mount.router)!;
      expect(layer.regexp?.test(mount.prefix), mount.prefix).toBe(true);
    }
  });

  it("guards every registered operator route except the two login handlers", async () => {
    const mount = mounts.find(({ tier }) => tier === "operator")!;
    const routes = discoverRoutes(mount.router).filter(
      ({ method, path }) => path !== "/login" || !["get", "post"].includes(method),
    );
    expect(routes.length).toBeGreaterThan(20);
    for (const route of routes) {
      const response = await request(app)[route.method](requestPath(mount.prefix, route.path));
      expect(response.status, `${route.method} ${route.path}`).toBe(401);
      expect(response.body).toEqual({ error: "Authentication required" });
    }
  });

  it("guards every registered machine route at its tier mount", async () => {
    const mount = mounts.find(({ tier }) => tier === "machine")!;
    const routes = discoverRoutes(mount.router);
    expect(routes.length).toBeGreaterThanOrEqual(3);
    for (const route of routes) {
      await request(app)[route.method](requestPath(mount.prefix, route.path)).expect(401);
    }
  });

  it("keeps login and the declared public routes outside authentication", async () => {
    await request(app).get("/admin/v1/login").expect(200).expect("content-type", /html/);
    await request(app).get("/health").expect(200);
    await request(app).get("/api").expect(200);
    await request(app).get("/openapi.json").expect(200);
  });

  it("parses a form login through the full application middleware stack", async () => {
    await request(app)
      .post("/admin/v1/login")
      .type("form")
      .send({ username: "admin", password: "anything", return_to: "/admin/v1/" })
      .expect(303)
      .expect("location", "/admin/v1/")
      .expect("set-cookie", /walrus_session=/);
  });
});
