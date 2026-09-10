import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../src/main.js";
import { createPackagesRouter, type PackagesRouteDeps } from "../../src/routes/packages.js";
import express from "express";
import { testOperatorAuth } from "../helpers/authn.js";

function packagesDeps(): PackagesRouteDeps {
  return {
    listEnabledPackages: async () => [],
    getPackage: async () => ({
      name: "uv",
      display_name: "uv",
      vendor: "Astral",
      description: null,
      website: null,
      config_hash: "x",
      enabled: true,
      removed_at: null,
      cve_version_extract: null,
      created_at: new Date(),
      updated_at: new Date(),
    }),
    listVersionGroups: async () => [],
    listVersionGroupsWithLts: async () => [],
    getEarliestCoolingOffInGroup: async () => null,
    listAvailableVersionsByGroup: async () => [],
    listAffectsForPackage: async () => [],
    listVersions: async () => [],
    listAvailableVersionsInGroup: async () => [
      {
        id: 2,
        package_name: "uv",
        version: "0.6.2",
        version_group: "0.6",
        is_lts: false,
        discovered_at: new Date(),
        version_sort: "0000.0006.0002",
      },
    ],
    listArtifactsForVersion: async () => [
      {
        id: 20,
        version_id: 2,
        os: "linux",
        arch: "x86-64",
        filename: "uv.tar.gz",
        gcs_path: "uv/0.6.2/linux/x86-64/uv.tar.gz",
        file_size: 99,
        checksum: "fff",
        checksum_type: "sha256",
        upstream_url: "https://example.test/uv.tar.gz",
        source_checksum: null,
        source_file_size: null,
        transform: null,
        status: "available",
        error_message: null,
        download_started_at: null,
        download_completed_at: null,
        removed_at: null,
        created_at: new Date(),
      },
    ],
    getRecentSyncJob: async () => null,
    triggerOnDemandSync: async () => {},
  };
}

const BASE_PATH = "/corp-walrus";

function buildApp() {
  const auth = testOperatorAuth();
  const app = createApp({
    basePath: BASE_PATH,
    operatorAuth: auth.runtime,
    internalAuth: (_req, res) => res.status(401).end(),
    health: { checkDatabase: async () => undefined },
  });
  return { app, bearer: auth.bearer };
}

describe("WALRUS_BASE_PATH (createApp basePath override)", () => {
  it("mounts the whole app under the configured prefix and not at root", async () => {
    const { app } = buildApp();
    await request(app).get("/").expect(404);
    await request(app).get(`${BASE_PATH}/`).expect(200).expect("content-type", /html/);
  });

  it("prefixes every link on the landing page", async () => {
    const { app } = buildApp();
    const response = await request(app).get(`${BASE_PATH}/`).expect(200);
    for (const href of [
      "/api",
      "/health",
      "/app/status",
      "/metrics",
      "/openapi.json",
      "/admin/v1/login?return_to=",
    ]) {
      expect(response.text).toContain(`href="${BASE_PATH}${href}`);
    }
  });

  it("redirects the bare /admin shortcut to the prefixed admin root", async () => {
    const { app } = buildApp();
    const response = await request(app).get(`${BASE_PATH}/admin`).expect(302);
    expect(response.headers.location).toBe(`${BASE_PATH}/admin/v1/`);
  });

  it("redirects a browser login to the prefixed admin root and sets a prefixed session cookie", async () => {
    const { app } = buildApp();
    const response = await request(app)
      .post(`${BASE_PATH}/admin/v1/login`)
      .type("form")
      .send({ username: "admin", password: "anything", return_to: `${BASE_PATH}/admin/v1/` })
      .expect(303);
    expect(response.headers.location).toBe(`${BASE_PATH}/admin/v1/`);
    const cookie = response.headers["set-cookie"]?.[0];
    expect(cookie).toContain(`Path=${BASE_PATH}/admin/v1`);
  });

  it("serves the static editor bundle script prefixed on the validate page", async () => {
    const { app, bearer } = buildApp();
    const response = await request(app)
      .get(`${BASE_PATH}/admin/v1/validate`)
      .set("Authorization", `Bearer ${bearer}`)
      .expect(200);
    expect(response.text).toContain(`src="${BASE_PATH}/static/editor-bundle.js"`);
  });

  it("keeps /health (and /app/health) reachable unprefixed for the Cloud Run probe, as well as prefixed", async () => {
    const { app } = buildApp();
    await request(app).get("/health").expect(200);
    await request(app).get("/app/health").expect(200);
    await request(app).get(`${BASE_PATH}/health`).expect(200);
  });

  it("declares the configured base path as the OpenAPI servers[] entry", async () => {
    const { app } = buildApp();
    const response = await request(app).get(`${BASE_PATH}/openapi.json`).expect(200);
    expect(response.body.servers).toEqual([{ url: BASE_PATH }]);
  });

  it("reports the effective base path on /app/status", async () => {
    const { app } = buildApp();
    const prefixed = await request(app).get(`${BASE_PATH}/app/status`).expect(200);
    expect(prefixed.body.base_path).toBe(BASE_PATH);
    // Same deployment-wide value whichever of the two mount points answered.
    const unprefixed = await request(app).get("/app/status").expect(200);
    expect(unprefixed.body.base_path).toBe(BASE_PATH);
  });
});

describe("createPackagesRouter basePath (download_url)", () => {
  function buildPackagesApp(basePath: string) {
    const app = express();
    app.use("/api/v1/packages", createPackagesRouter(packagesDeps(), basePath));
    return app;
  }

  it("prefixes download_url with the configured base path", async () => {
    const app = buildPackagesApp("/corp-walrus");
    const response = await request(app)
      .get("/api/v1/packages/uv/versions/0.6/latest?os=linux&arch=x86-64")
      .expect(200);
    expect(response.body.artifact.download_url).toBe("/corp-walrus/download/uv/0.6.2/linux/x86-64");
  });

  it("leaves download_url unprefixed when no base path is configured", async () => {
    const app = buildPackagesApp("");
    const response = await request(app)
      .get("/api/v1/packages/uv/versions/0.6/latest?os=linux&arch=x86-64")
      .expect(200);
    expect(response.body.artifact.download_url).toBe("/download/uv/0.6.2/linux/x86-64");
  });
});
