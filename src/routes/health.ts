import { Router } from "express";
import { HealthResponseSchema, StatusResponseSchema } from "./schemas.js";

export const HEALTH_GRACE_PERIOD_MS = 300_000;
export const DATABASE_HEALTH_CACHE_MS = 60_000;

export interface ApplicationMetadata {
  gitUrl: string;
  version: string;
}

export interface ApplicationStatusDetails {
  vuln_data_freshness: unknown;
  vuln_sync_status: unknown;
  degradations: unknown[];
}

export interface HealthRouterDeps {
  metadata: ApplicationMetadata;
  startedAt: Date;
  checkDatabase: () => Promise<void>;
  getStatusDetails: () => Promise<ApplicationStatusDetails>;
  now?: () => Date;
  gracePeriodMs?: number;
  databaseHealthCacheMs?: number;
}

export function createHealthRouter(deps: HealthRouterDeps): Router {
  const router = Router();
  const now = deps.now ?? (() => new Date());
  const gracePeriodMs = deps.gracePeriodMs ?? HEALTH_GRACE_PERIOD_MS;
  const databaseHealthCacheMs = deps.databaseHealthCacheMs ?? DATABASE_HEALTH_CACHE_MS;
  let cachedDatabaseHealth: { checkedAt: number; available: boolean } | undefined;
  let databaseHealthProbe: Promise<boolean> | undefined;

  function getDatabaseAvailability(current: Date): Promise<boolean> {
    const currentMs = current.getTime();
    if (
      cachedDatabaseHealth &&
      currentMs >= cachedDatabaseHealth.checkedAt &&
      currentMs - cachedDatabaseHealth.checkedAt < databaseHealthCacheMs
    ) {
      return Promise.resolve(cachedDatabaseHealth.available);
    }
    if (databaseHealthProbe) return databaseHealthProbe;

    databaseHealthProbe = deps
      .checkDatabase()
      .then(
        () => true,
        () => false,
      )
      .then((available) => {
        cachedDatabaseHealth = { checkedAt: currentMs, available };
        return available;
      })
      .finally(() => {
        databaseHealthProbe = undefined;
      });
    return databaseHealthProbe;
  }

  async function getHealth() {
    const current = now();
    const inGracePeriod = current.getTime() - deps.startedAt.getTime() < gracePeriodMs;
    const databaseAvailable = await getDatabaseAvailability(current);

    return HealthResponseSchema.parse({
      isAvailable: inGracePeriod || databaseAvailable,
      gitUrl: deps.metadata.gitUrl,
      ts: current.toISOString(),
      started: deps.startedAt.toISOString(),
      inGracePeriod,
      version: deps.metadata.version,
    });
  }

  router.get(["/health", "/app/health"], async (_req, res, next) => {
    try {
      const health = await getHealth();
      res.status(health.isAvailable ? 200 : 503).json(health);
    } catch (error) {
      next(error);
    }
  });

  router.get("/app/status", async (_req, res, next) => {
    try {
      const [health, details] = await Promise.all([getHealth(), deps.getStatusDetails()]);
      const status = StatusResponseSchema.parse({ ...health, ...details });
      res.status(status.isAvailable ? 200 : 503).json(status);
    } catch (error) {
      next(error);
    }
  });

  return router;
}
