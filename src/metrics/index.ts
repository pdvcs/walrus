import { collectDefaultMetrics, Counter, Gauge, Histogram, Registry } from "@prometheus-io/client";
import { Request, RequestHandler, Router } from "express";
import { Pool } from "pg";
import { z } from "zod";
import { log } from "../common/log.js";
import type { MetricsSnapshot } from "../services/metrics-snapshot.js";
import { MetricsResponseSchema } from "../routes/schemas.js";

const DATABASE_CACHE_MS = 60_000;
const PACKAGE_STATES = ["enabled", "disabled", "removed"] as const;
const VULN_SOURCES = ["nvd", "kev", "osv", "cvss"] as const;
const VULN_STATES = ["never", "running", "succeeded", "failed"] as const;
const DEGRADATION_COMPONENTS = [
  "vuln-sync-nvd",
  "vuln-sync-kev",
  "vuln-sync-osv",
  "vuln-sync-cvss",
  "vuln-backfill",
] as const;

export interface MetricsRuntimeOptions {
  pool: Pool;
  version: string;
  basePath: string;
  loadSnapshot: () => Promise<MetricsSnapshot>;
  now?: () => Date;
  databaseCacheMs?: number;
}

export interface MetricsRuntime {
  middleware: RequestHandler;
  router: Router;
  registry: Registry;
  shutdown: () => Promise<void>;
}

function metricOptions<T extends string>(
  registry: Registry,
  options: { name: string; help: string; labelNames?: readonly T[] },
) {
  return { ...options, registers: [registry] };
}

export function createMetricsRuntime(options: MetricsRuntimeOptions): MetricsRuntime {
  const registry = new Registry();
  const now = options.now ?? (() => new Date());
  collectDefaultMetrics({ register: registry, prefix: "walrus_" });

  const buildInfo = new Gauge(
    metricOptions(registry, {
      name: "walrus_build_info",
      help: "Build information for this Walrus process.",
      labelNames: ["version"] as const,
    }),
  );
  buildInfo.set({ version: options.version }, 1);

  const httpRequests = new Counter(
    metricOptions(registry, {
      name: "walrus_http_requests_total",
      help: "Completed HTTP requests by canonical route and response status.",
      labelNames: ["method", "route", "status_code"] as const,
    }),
  );
  const httpDuration = new Histogram({
    ...metricOptions(registry, {
      name: "walrus_http_request_duration_seconds",
      help: "Duration of completed non-download HTTP requests.",
      labelNames: ["method", "route"] as const,
    }),
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
  });
  const httpRequestSize = new Histogram({
    ...metricOptions(registry, {
      name: "walrus_http_request_size_bytes",
      help: "Declared size of non-download HTTP request bodies.",
      labelNames: ["method", "route"] as const,
    }),
    buckets: [100, 1_000, 10_000, 100_000, 1_000_000],
  });
  const httpResponseSize = new Histogram({
    ...metricOptions(registry, {
      name: "walrus_http_response_size_bytes",
      help: "Declared size of completed non-download HTTP responses.",
      labelNames: ["method", "route"] as const,
    }),
    buckets: [100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000],
  });
  const inFlight = new Gauge(
    metricOptions(registry, {
      name: "walrus_http_requests_in_flight",
      help: "HTTP requests currently being handled.",
    }),
  );
  const downloadBytes = new Counter(
    metricOptions(registry, {
      name: "walrus_download_bytes_total",
      help: "Bytes in completed full and ranged artifact downloads.",
      labelNames: ["package"] as const,
    }),
  );
  const downloadDuration = new Histogram({
    ...metricOptions(registry, {
      name: "walrus_download_duration_seconds",
      help: "Duration of completed full and ranged artifact downloads.",
      labelNames: ["package", "result"] as const,
    }),
    buckets: [1, 5, 15, 30, 60, 120, 300, 600, 900, 1_800, 3_600],
  });

  const poolConnections = new Gauge(
    metricOptions(registry, {
      name: "walrus_database_pool_connections",
      help: "PostgreSQL pool connections by state.",
      labelNames: ["state"] as const,
    }),
  );
  const poolWaiting = new Gauge(
    metricOptions(registry, {
      name: "walrus_database_pool_waiting_requests",
      help: "Requests waiting for a PostgreSQL pool connection.",
    }),
  );
  const databaseAvailable = new Gauge(
    metricOptions(registry, {
      name: "walrus_database_available",
      help: "Whether the latest database metrics collection succeeded.",
    }),
  );
  const collectionSuccess = new Gauge(
    metricOptions(registry, {
      name: "walrus_metrics_collection_success",
      help: "Whether the latest metrics collection succeeded.",
      labelNames: ["collector"] as const,
    }),
  );
  const collectionDuration = new Histogram({
    ...metricOptions(registry, {
      name: "walrus_metrics_collection_duration_seconds",
      help: "Duration of metrics collection.",
      labelNames: ["collector"] as const,
    }),
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5],
  });
  const collectionLastSuccess = new Gauge(
    metricOptions(registry, {
      name: "walrus_metrics_collection_last_success_timestamp_seconds",
      help: "Unix timestamp of the last successful metrics collection.",
      labelNames: ["collector"] as const,
    }),
  );
  const collectionAge = new Gauge(
    metricOptions(registry, {
      name: "walrus_metrics_collection_age_seconds",
      help: "Age of the last successful metrics collection, or positive infinity before the first success.",
      labelNames: ["collector"] as const,
    }),
  );

  databaseAvailable.set(0);
  collectionSuccess.set({ collector: "database" }, 0);
  collectionAge.set({ collector: "database" }, Number.POSITIVE_INFINITY);

  const packages = new Gauge(
    metricOptions(registry, {
      name: "walrus_packages",
      help: "Packages by lifecycle state.",
      labelNames: ["state"] as const,
    }),
  );
  const artifacts = new Gauge(
    metricOptions(registry, {
      name: "walrus_artifacts",
      help: "Artifacts by package and lifecycle state.",
      labelNames: ["package", "status"] as const,
    }),
  );
  const artifactStoredBytes = new Gauge(
    metricOptions(registry, {
      name: "walrus_artifact_stored_bytes",
      help: "Stored bytes in available artifacts by package.",
      labelNames: ["package"] as const,
    }),
  );
  const artifactOldestAge = new Gauge(
    metricOptions(registry, {
      name: "walrus_artifact_oldest_age_seconds",
      help: "Age of the oldest actionable artifact by package and state.",
      labelNames: ["package", "status"] as const,
    }),
  );
  const packageSyncRunning = new Gauge(
    metricOptions(registry, {
      name: "walrus_package_sync_running",
      help: "Currently running package sync jobs.",
      labelNames: ["package"] as const,
    }),
  );
  const packageSyncLastAttempt = timestampGauge(
    registry,
    "walrus_package_sync_last_attempt_timestamp_seconds",
    "Unix timestamp of the latest package sync attempt.",
    ["package"],
  );
  const packageSyncLastSuccess = timestampGauge(
    registry,
    "walrus_package_sync_last_success_timestamp_seconds",
    "Unix timestamp of the latest successful package sync.",
    ["package"],
  );
  const packageSyncLastFailure = timestampGauge(
    registry,
    "walrus_package_sync_last_failure_timestamp_seconds",
    "Unix timestamp of the latest failed package sync.",
    ["package"],
  );
  const packageSyncLastDuration = new Gauge(
    metricOptions(registry, {
      name: "walrus_package_sync_last_duration_seconds",
      help: "Duration of the latest completed package sync job.",
      labelNames: ["package"] as const,
    }),
  );
  const packageSyncLastResult = new Gauge(
    metricOptions(registry, {
      name: "walrus_package_sync_last_result",
      help: "One-hot result and trigger of the latest package sync job.",
      labelNames: ["package", "trigger", "result"] as const,
    }),
  );
  const packageSyncLastArtifacts = new Gauge(
    metricOptions(registry, {
      name: "walrus_package_sync_last_artifacts",
      help: "Artifact outcomes from the latest package sync job.",
      labelNames: ["package", "outcome"] as const,
    }),
  );

  const vulnLastAttempt = timestampGauge(
    registry,
    "walrus_vulnerability_sync_last_attempt_timestamp_seconds",
    "Unix timestamp of the latest vulnerability source attempt.",
    ["source"],
  );
  const vulnLastSuccess = timestampGauge(
    registry,
    "walrus_vulnerability_sync_last_success_timestamp_seconds",
    "Unix timestamp of the latest successful vulnerability source sync.",
    ["source"],
  );
  const vulnLastFailure = timestampGauge(
    registry,
    "walrus_vulnerability_sync_last_failure_timestamp_seconds",
    "Unix timestamp of the latest failed vulnerability source sync.",
    ["source"],
  );
  const vulnState = new Gauge(
    metricOptions(registry, {
      name: "walrus_vulnerability_sync_state",
      help: "One-hot state of each vulnerability source sync.",
      labelNames: ["source", "state"] as const,
    }),
  );
  const degradation = new Gauge(
    metricOptions(registry, {
      name: "walrus_vulnerability_degradation_active",
      help: "Whether a fixed vulnerability component is currently degraded.",
      labelNames: ["component"] as const,
    }),
  );
  const enrichmentBacklog = new Gauge(
    metricOptions(registry, {
      name: "walrus_vulnerability_enrichment_backlog",
      help: "CVEs awaiting CVSS enrichment.",
    }),
  );
  const backfillJobs = new Gauge(
    metricOptions(registry, {
      name: "walrus_vulnerability_backfill_jobs",
      help: "Active vulnerability backfill jobs by status.",
      labelNames: ["status"] as const,
    }),
  );
  const blockedVersions = new Gauge(
    metricOptions(registry, {
      name: "walrus_versions_blocked",
      help: "Versions currently blocked by the critical vulnerability gate.",
      labelNames: ["package"] as const,
    }),
  );
  const activeSuppressions = new Gauge(
    metricOptions(registry, {
      name: "walrus_cve_suppressions_active",
      help: "Active CVE suppressions.",
    }),
  );
  const nextSuppressionExpiry = timestampGauge(
    registry,
    "walrus_cve_suppression_next_expiry_timestamp_seconds",
    "Unix timestamp of the next active CVE suppression expiry.",
    [],
  );

  const databaseGauges = [
    packages,
    artifacts,
    artifactStoredBytes,
    artifactOldestAge,
    packageSyncRunning,
    packageSyncLastAttempt,
    packageSyncLastSuccess,
    packageSyncLastFailure,
    packageSyncLastDuration,
    packageSyncLastResult,
    packageSyncLastArtifacts,
    vulnLastAttempt,
    vulnLastSuccess,
    vulnLastFailure,
    vulnState,
    degradation,
    enrichmentBacklog,
    backfillJobs,
    blockedVersions,
    activeSuppressions,
    nextSuppressionExpiry,
  ];

  let lastCollectedAt = 0;
  let collection: Promise<void> | undefined;

  function applySnapshot(snapshot: MetricsSnapshot): void {
    for (const gauge of databaseGauges) gauge.reset();

    for (const state of PACKAGE_STATES) packages.set({ state }, 0);
    for (const row of snapshot.packages) packages.set({ state: row.state }, row.count);

    const storedBytes = new Map<string, number>();
    for (const row of snapshot.artifacts) {
      artifacts.set({ package: row.package_name, status: row.status }, row.count);
      storedBytes.set(
        row.package_name,
        (storedBytes.get(row.package_name) ?? 0) + row.stored_bytes,
      );
      if (row.oldest_at) {
        artifactOldestAge.set(
          { package: row.package_name, status: row.status },
          Math.max(0, (now().getTime() - row.oldest_at.getTime()) / 1_000),
        );
      }
    }
    for (const [packageName, bytes] of storedBytes) {
      artifactStoredBytes.set({ package: packageName }, bytes);
    }

    for (const row of snapshot.packageSyncs) {
      const labels = { package: row.package_name };
      packageSyncRunning.set(labels, row.running);
      packageSyncLastAttempt.set(labels, seconds(row.last_attempt));
      if (row.last_success) packageSyncLastSuccess.set(labels, seconds(row.last_success));
      if (row.last_failure) packageSyncLastFailure.set(labels, seconds(row.last_failure));
      if (row.latest_completed_at) {
        packageSyncLastDuration.set(
          labels,
          Math.max(
            0,
            (row.latest_completed_at.getTime() - row.latest_started_at.getTime()) / 1_000,
          ),
        );
      }
      packageSyncLastResult.set(
        {
          ...labels,
          trigger: row.latest_trigger,
          result: row.latest_status === "completed" ? "success" : row.latest_status,
        },
        1,
      );
      packageSyncLastArtifacts.set({ ...labels, outcome: "queued" }, row.artifacts_queued);
      packageSyncLastArtifacts.set({ ...labels, outcome: "downloaded" }, row.artifacts_downloaded);
      packageSyncLastArtifacts.set({ ...labels, outcome: "failed" }, row.artifacts_failed);
    }

    for (const source of VULN_SOURCES) {
      const status = snapshot.vulnSync[source];
      if (status.last_attempt) vulnLastAttempt.set({ source }, isoSeconds(status.last_attempt));
      if (status.last_success) vulnLastSuccess.set({ source }, isoSeconds(status.last_success));
      if (status.last_failure) vulnLastFailure.set({ source }, isoSeconds(status.last_failure));
      const currentState = !status.last_attempt
        ? "never"
        : status.last_ok === null
          ? "running"
          : status.last_ok
            ? "succeeded"
            : "failed";
      for (const state of VULN_STATES) {
        vulnState.set({ source, state }, state === currentState ? 1 : 0);
      }
    }

    const activeComponents = new Set(snapshot.degradations.map((item) => item.component));
    for (const component of DEGRADATION_COMPONENTS) {
      degradation.set({ component }, activeComponents.has(component) ? 1 : 0);
    }
    enrichmentBacklog.set(snapshot.vulnerabilityEnrichmentBacklog);
    for (const status of ["queued", "running"] as const) backfillJobs.set({ status }, 0);
    for (const row of snapshot.vulnerabilityBackfills) {
      backfillJobs.set({ status: row.status }, row.count);
    }
    for (const row of snapshot.blockedVersions) {
      blockedVersions.set({ package: row.package_name }, row.count);
    }
    activeSuppressions.set(snapshot.activeSuppressions);
    if (snapshot.nextSuppressionExpiry) {
      nextSuppressionExpiry.set(isoSeconds(snapshot.nextSuppressionExpiry));
    }
  }

  async function refreshDatabaseMetrics(): Promise<void> {
    const currentMs = now().getTime();
    if (
      currentMs >= lastCollectedAt &&
      currentMs - lastCollectedAt < (options.databaseCacheMs ?? DATABASE_CACHE_MS)
    ) {
      return;
    }
    if (collection) return collection;

    collection = (async () => {
      const started = process.hrtime.bigint();
      try {
        const snapshot = await options.loadSnapshot();
        applySnapshot(snapshot);
        lastCollectedAt = now().getTime();
        databaseAvailable.set(1);
        collectionSuccess.set({ collector: "database" }, 1);
        collectionLastSuccess.set({ collector: "database" }, lastCollectedAt / 1_000);
      } catch (err) {
        databaseAvailable.set(0);
        collectionSuccess.set({ collector: "database" }, 0);
        log.warn({ err }, "Could not refresh database-backed Prometheus metrics");
      } finally {
        collectionDuration.observe(
          { collector: "database" },
          Number(process.hrtime.bigint() - started) / 1e9,
        );
      }
    })().finally(() => {
      collection = undefined;
    });
    return collection;
  }

  const middleware: RequestHandler = (req, res, next) => {
    if (isMetricsRequest(req, options.basePath)) {
      next();
      return;
    }
    const started = process.hrtime.bigint();
    let completed = false;
    inFlight.inc();

    const finishInFlight = () => {
      if (completed) return false;
      completed = true;
      inFlight.dec();
      return true;
    };
    res.once("close", finishInFlight);
    res.once("finish", () => {
      if (!finishInFlight()) return;
      const route = canonicalRoute(req, options.basePath);
      if (route === "/metrics") return;
      const method = req.method;
      const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
      httpRequests.inc({ method, route, status_code: String(res.statusCode) });

      const metricsPackage = z.string().safeParse(res.locals.metricsPackage);
      const isDownload =
        metricsPackage.success && (res.statusCode === 200 || res.statusCode === 206);
      if (isDownload) {
        const result = res.statusCode === 206 ? "partial" : "full";
        downloadDuration.observe({ package: metricsPackage.data, result }, elapsed);
        const selectedBytes = z
          .number()
          .finite()
          .nonnegative()
          .safeParse(res.locals.metricsDownloadBytes);
        if (selectedBytes.success) {
          downloadBytes.inc({ package: metricsPackage.data }, selectedBytes.data);
        }
        return;
      }

      httpDuration.observe({ method, route }, elapsed);
      const requestLength = contentLength(req.headers["content-length"]);
      if (requestLength !== null) httpRequestSize.observe({ method, route }, requestLength);
      const responseLength = contentLength(res.getHeader("Content-Length"));
      if (responseLength !== null) httpResponseSize.observe({ method, route }, responseLength);
    });
    next();
  };

  const router = Router();
  router.get("/", async (_req, res, next) => {
    try {
      poolConnections.reset();
      poolConnections.set({ state: "total" }, options.pool.totalCount);
      poolConnections.set({ state: "idle" }, options.pool.idleCount);
      poolWaiting.set(options.pool.waitingCount);
      collectionAge.set(
        { collector: "database" },
        lastCollectedAt === 0
          ? Number.POSITIVE_INFINITY
          : Math.max(0, (now().getTime() - lastCollectedAt) / 1_000),
      );
      const body = MetricsResponseSchema.parse(await registry.metrics());
      res.setHeader("Cache-Control", "no-store");
      res.setHeader("Content-Type", registry.contentType);
      res.once("finish", () => {
        void refreshDatabaseMetrics();
      });
      res.status(200).send(body);
    } catch (err) {
      next(err);
    }
  });

  return {
    middleware,
    router,
    registry,
    shutdown: () => {
      registry.clear();
      return Promise.resolve();
    },
  };
}

function timestampGauge<T extends string>(
  registry: Registry,
  name: string,
  help: string,
  labelNames: readonly T[],
): Gauge<T> {
  return new Gauge(metricOptions(registry, { name, help, labelNames }));
}

function seconds(value: Date): number {
  return value.getTime() / 1_000;
}

function isoSeconds(value: string): number {
  return Date.parse(value) / 1_000;
}

function contentLength(value: string | number | string[] | undefined): number | null {
  if (Array.isArray(value)) return null;
  const parsed = typeof value === "number" ? value : value === undefined ? NaN : Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

export function canonicalRoute(req: Request, basePath: string): string {
  const route = (req as unknown as { route?: { path?: unknown } }).route;
  const routePath = route?.path;
  const configuredPath = Array.isArray(routePath)
    ? ((routePath as unknown[]).find(
        (path): path is string => typeof path === "string" && req.path === path,
      ) ??
      (routePath as unknown[]).find(
        (path): path is string => typeof path === "string" && req.path.endsWith(path),
      ))
    : routePath;
  if (typeof configuredPath !== "string") return "unmatched";
  const matchedRoute = `${req.baseUrl}${configuredPath}`.replace(/\/+/g, "/");
  if (basePath && matchedRoute.startsWith(`${basePath}/`)) {
    return matchedRoute.slice(basePath.length);
  }
  return matchedRoute || "/";
}

function isMetricsRequest(req: Request, basePath: string): boolean {
  const path = `${basePath}/metrics`;
  return req.path === path || req.path === `${path}/`;
}
