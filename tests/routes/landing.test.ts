import request from "supertest";
import { describe, expect, it } from "vitest";
import packageMetadata from "../../package.json";
import { createApp } from "../../src/main.js";
import { testOperatorAuth } from "../helpers/authn.js";

describe("public landing page", () => {
  const auth = testOperatorAuth();
  const app = createApp({
    operatorAuth: auth.runtime,
    internalAuth: (_req, res) => res.status(401).end(),
    health: { checkDatabase: async () => undefined },
  });

  it("introduces Walrus, reports the package version, and links its entry points", async () => {
    const response = await request(app).get("/").expect(200).expect("content-type", /html/);
    expect(response.headers.location).toBeUndefined();
    expect(response.text).toContain("<h1>Walrus</h1>");
    expect(response.text).toContain(`v${packageMetadata.version}`);
    expect(response.text).toContain(
      'href="/admin/v1/login?return_to=%2Fadmin%2Fv1%2F">Log in as admin</a>',
    );
    for (const href of ["/api", "/health", "/app/status", "/openapi.json"]) {
      expect(response.text).toContain(`href="${href}"`);
    }
  });

  it("takes the landing-page login flow to the admin dashboard", async () => {
    await request(app)
      .get("/admin/v1/login?return_to=%2Fadmin%2Fv1%2F")
      .expect(200)
      .expect("content-type", /html/);
    await request(app)
      .post("/admin/v1/login")
      .type("form")
      .send({ username: "admin", password: "anything", return_to: "/admin/v1/" })
      .expect(303)
      .expect("location", "/admin/v1/");
  });

  it("publishes the landing-page HTML contract in OpenAPI", async () => {
    const spec = (await request(app).get("/openapi.json")).body;
    expect(spec.paths["/"].get.responses["200"].content).toHaveProperty("text/html");
    expect(spec.components.schemas).toHaveProperty("LandingPageResponse");
  });
});
