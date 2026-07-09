import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import { runMigrations } from "../../src/db/client.js";
import { createApp } from "../../src/main.js";

describe("GET /health", () => {
  beforeAll(async () => {
    await runMigrations();
  });

  it("includes vuln_data_freshness with per-source nullable timestamps and passes its schema", async () => {
    const app = createApp();
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
    expect(res.body.service).toBe("walrus");
    expect(res.body).toHaveProperty("vuln_data_freshness");
    // Each source key exists (value may be null before a first sync).
    const f = res.body.vuln_data_freshness;
    expect(f).toHaveProperty("nvd_last_sync");
    expect(f).toHaveProperty("kev_last_sync");
    expect(f).toHaveProperty("osv_last_sync");
  });
});
