import fs from "fs";
import os from "os";
import path from "path";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../../src/main.js";
import { testOperatorAuth } from "../helpers/authn.js";

const auth = testOperatorAuth();
const base = {
  operatorAuth: auth.runtime,
  internalAuth: (_req: unknown, res: { status: (n: number) => { end: () => void } }) =>
    res.status(401).end(),
  health: { checkDatabase: async () => undefined },
} as unknown as Parameters<typeof createApp>[0];

describe("nav logo routes", () => {
  let dir: string;
  let pub: string;
  let adm: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-brand-"));
    pub = path.join(dir, "acme.png");
    adm = path.join(dir, "acme-admin.webp");
    fs.writeFileSync(pub, Buffer.from("public-bytes"));
    fs.writeFileSync(adm, Buffer.from("admin-bytes"));
  });
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("serves the bundled day and night logos by default, with no login", async () => {
    const app = createApp(base);
    const day = await request(app).get("/brand/logo").expect(200);
    const night = await request(app).get("/brand/admin-logo").expect(200);
    expect(day.headers["content-type"]).toBe("image/jpeg");
    expect(night.headers["content-type"]).toBe("image/jpeg");
    expect(day.body.length).toBeGreaterThan(1000);
    // Two different pictures, not the same file twice.
    expect(Buffer.compare(day.body, night.body)).not.toBe(0);
  });

  it("serves whichever files are configured, typed by their extension", async () => {
    const app = createApp({ ...base, logoFiles: { public: pub, admin: adm } });
    const day = await request(app).get("/brand/logo").expect(200);
    expect(day.headers["content-type"]).toBe("image/png");
    expect(day.body.toString()).toBe("public-bytes");
    const night = await request(app).get("/brand/admin-logo").expect(200);
    expect(night.headers["content-type"]).toBe("image/webp");
    expect(night.body.toString()).toBe("admin-bytes");
  });

  it("is cacheable and refuses content sniffing", async () => {
    const app = createApp({ ...base, logoFiles: { public: pub, admin: adm } });
    const res = await request(app).get("/brand/logo").expect(200);
    expect(res.headers["cache-control"]).toMatch(/max-age=3600/);
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
  });

  it("answers 404, not a 500, if the file has gone missing since boot", async () => {
    const app = createApp({
      ...base,
      logoFiles: { public: path.join(dir, "gone.png"), admin: adm },
    });
    await request(app).get("/brand/logo").expect(404);
  });

  it("sits under the base path like every other route", async () => {
    const app = createApp({
      ...base,
      basePath: "/corp-walrus",
      logoFiles: { public: pub, admin: adm },
    });
    await request(app).get("/corp-walrus/brand/logo").expect(200);
    await request(app).get("/corp-walrus/brand/admin-logo").expect(200);
    await request(app).get("/brand/logo").expect(404);
  });

  it("points the nav at those URLs on both the public and admin pages", async () => {
    const app = createApp({ ...base, logoFiles: { public: pub, admin: adm } });
    const landing = await request(app).get("/").expect(200);
    expect(landing.text).toContain('src="/brand/logo"');
    expect(landing.text).not.toContain("/brand/admin-logo");
    const admin = await request(app)
      .get("/admin/v1/validate")
      .set("Authorization", `Bearer ${auth.bearer}`)
      .expect(200);
    expect(admin.text).toContain('src="/brand/admin-logo"');
  });
});
