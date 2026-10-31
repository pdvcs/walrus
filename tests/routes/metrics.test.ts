import request from "supertest";
import express from "express";
import { describe, expect, it, vi } from "vitest";
import packageMetadata from "../../package.json";
import { pool } from "../../src/db/client.js";
import { createApp } from "../../src/main.js";
import { createMetricsRuntime } from "../../src/metrics/index.js";
import type { MetricsSnapshot } from "../../src/services/metrics-snapshot.js";

function emptySnapshot(packageCount = 3): MetricsSnapshot {
  const never = {
    last_attempt: null,
    last_success: null,
    last_failure: null,
    last_ok: null,
  };
  return {
    packages: [{ state: "enabled", count: packageCount }],
    artifacts: [],
    packageSyncs: [],
    vulnSync: { nvd: never, kev: never, osv: never, cvss: never },
    degradations: [],
    vulnerabilityEnrichmentBacklog: 7,
    vulnerabilityBackfills: [],
    blockedVersions: [],
    activeSuppressions: 0,
    nextSuppressionExpiry: null,
  };
}

function buildApp(
  overrides: {
    basePath?: string;
    loadSnapshot?: () => Promise<MetricsSnapshot>;
    now?: () => Date;
  } = {},
) {
  return createApp({
    basePath: overrides.basePath,
    health: { checkDatabase: async () => undefined },
    metrics: {
      loadSnapshot: overrides.loadSnapshot ?? (async () => emptySnapshot()),
      now: overrides.now,
      databaseCacheMs: 60_000,
    },
  });
}

describe("Prometheus metrics", () => {
  it("serves runtime and database-backed metrics in Prometheus text format", async () => {
    const loadSnapshot = vi.fn(async () => emptySnapshot());
    const app = buildApp({ loadSnapshot });
    const initialResponse = await request(app).get("/metrics").expect(200);

    expect(initialResponse.headers["content-type"]).toMatch(
      /^text\/plain; (?=.*version=0\.0\.4)(?=.*charset=utf-8)/,
    );
    expect(initialResponse.headers["cache-control"]).toBe("no-store");
    expect(initialResponse.text).toContain("# HELP walrus_build_info");
    expect(initialResponse.text).toContain(
      `walrus_build_info{version="${packageMetadata.version}"} 1`,
    );
    expect(initialResponse.text).toContain(
      'walrus_metrics_collection_age_seconds{collector="database"} +Inf',
    );
    expect(initialResponse.text).toContain("walrus_http_requests_in_flight 0");
    expect(initialResponse.text.endsWith("\n")).toBe(true);

    await vi.waitFor(() => expect(loadSnapshot).toHaveBeenCalledOnce());
    const response = await request(app).get("/metrics").expect(200);
    expect(response.text).toContain('walrus_packages{state="enabled"} 3');
    expect(response.text).toContain("walrus_vulnerability_enrichment_backlog 7");
    expect(response.text).toContain(
      'walrus_metrics_collection_age_seconds{collector="database"} 0',
    );
  });

  it("mounts metrics only below WALRUS_BASE_PATH when configured", async () => {
    const app = buildApp({ basePath: "/corp-walrus" });

    await request(app).get("/metrics").expect(404);
    await request(app).get("/corp-walrus/health").expect(200);
    const response = await request(app).get("/corp-walrus/metrics").expect(200);
    expect(response.text).toContain(
      'walrus_http_requests_total{method="GET",route="/health",status_code="200"} 1',
    );
    expect(response.text).toContain("walrus_http_requests_in_flight 0");
  });

  it("records canonical API routes and never raw unmatched paths", async () => {
    const app = buildApp();
    await request(app).get("/health?token=secret-value").expect(200);
    await request(app).get("/attacker/value-123?token=secret-value").expect(404);

    const response = await request(app).get("/metrics").expect(200);
    expect(response.text).toContain(
      'walrus_http_requests_total{method="GET",route="/health",status_code="200"} 1',
    );
    expect(response.text).toContain(
      'walrus_http_requests_total{method="GET",route="unmatched",status_code="404"} 1',
    );
    expect(response.text).not.toContain("secret-value");
    expect(response.text).not.toContain("value-123");
  });

  it("caches database snapshots for 60 seconds", async () => {
    const loadSnapshot = vi
      .fn<() => Promise<MetricsSnapshot>>()
      .mockResolvedValueOnce(emptySnapshot(3))
      .mockResolvedValue(emptySnapshot(4));
    let nowMs = Date.parse("2026-09-10T12:00:00Z");
    const app = buildApp({ loadSnapshot, now: () => new Date(nowMs) });

    await request(app).get("/metrics").expect(200);
    await vi.waitFor(() => expect(loadSnapshot).toHaveBeenCalledOnce());
    nowMs += 59_999;
    const cached = await request(app).get("/metrics").expect(200);
    expect(cached.text).toContain('walrus_packages{state="enabled"} 3');
    expect(cached.text).toContain(
      'walrus_metrics_collection_age_seconds{collector="database"} 59.999',
    );
    expect(loadSnapshot).toHaveBeenCalledOnce();

    nowMs += 1;
    const stale = await request(app).get("/metrics").expect(200);
    expect(stale.text).toContain('walrus_packages{state="enabled"} 3');
    expect(stale.text).toContain('walrus_metrics_collection_age_seconds{collector="database"} 60');
    await vi.waitFor(() => expect(loadSnapshot).toHaveBeenCalledTimes(2));

    const refreshed = await request(app).get("/metrics").expect(200);
    expect(refreshed.text).toContain('walrus_packages{state="enabled"} 4');
  });

  it("does not wait for a database refresh before serving metrics", async () => {
    let resolveSnapshot: ((snapshot: MetricsSnapshot) => void) | undefined;
    const loadSnapshot = vi.fn(
      () =>
        new Promise<MetricsSnapshot>((resolve) => {
          resolveSnapshot = resolve;
        }),
    );
    const app = buildApp({ loadSnapshot });

    const response = await request(app).get("/metrics").expect(200);
    expect(response.text).toContain("# HELP walrus_process_cpu_user_seconds_total");
    await vi.waitFor(() => expect(loadSnapshot).toHaveBeenCalledOnce());

    resolveSnapshot?.(emptySnapshot());
  });

  it("counts completed download bytes from the selected range rather than Content-Length", async () => {
    const metrics = createMetricsRuntime({
      pool,
      version: "test",
      basePath: "",
      loadSnapshot: async () => emptySnapshot(),
    });
    const app = express();
    app.use(metrics.middleware);
    app.get("/download/:package", (_req, res) => {
      res.locals.metricsPackage = "uv";
      res.locals.metricsDownloadBytes = 17;
      res.status(206).send("chunk");
    });
    app.use("/metrics", metrics.router);

    await request(app).get("/download/untrusted-value").expect(206);
    const response = await request(app).get("/metrics").expect(200);
    expect(response.text).toContain('walrus_download_bytes_total{package="uv"} 17');
    expect(response.text).toContain(
      'walrus_download_duration_seconds_count{package="uv",result="partial"} 1',
    );
    expect(response.text).not.toContain("untrusted-value");
  });

  it("keeps process metrics scrapeable when the database collector fails", async () => {
    const loadSnapshot = vi
      .fn<() => Promise<MetricsSnapshot>>()
      .mockResolvedValueOnce(emptySnapshot())
      .mockRejectedValue(new Error("secret DB error"));
    let nowMs = Date.parse("2026-09-10T12:00:00Z");
    const app = buildApp({ loadSnapshot, now: () => new Date(nowMs) });
    await request(app).get("/metrics").expect(200);
    await vi.waitFor(() => expect(loadSnapshot).toHaveBeenCalledOnce());

    nowMs += 60_000;
    const stale = await request(app).get("/metrics").expect(200);
    expect(stale.text).toContain('walrus_packages{state="enabled"} 3');
    await vi.waitFor(() => expect(loadSnapshot).toHaveBeenCalledTimes(2));

    const response = await request(app).get("/metrics").expect(200);

    expect(response.text).toContain("walrus_database_available 0");
    expect(response.text).toContain('walrus_metrics_collection_success{collector="database"} 0');
    expect(response.text).toContain('walrus_packages{state="enabled"} 3');
    expect(response.text).toContain(
      'walrus_metrics_collection_age_seconds{collector="database"} 60',
    );
    expect(response.text).toContain("# HELP walrus_process_cpu_user_seconds_total");
    expect(response.text).not.toContain("secret DB error");
  });
});
