import { Router } from "express";
import { WatchlistResponseSchema } from "./schemas.js";
import type { WatchedPackageRow } from "../db/queries/packages.js";
import type { PostureResult } from "../services/posture.js";
import type { DataFreshness } from "../services/vuln-query.js";
import { VULN_DISCLAIMER } from "./schemas.js";

export interface WatchlistRouteDeps {
  listWatched: () => Promise<WatchedPackageRow[]>;
  /** Posture at the package's latest version. */
  getPosture: (name: string) => Promise<PostureResult | null>;
  getDataFreshness: () => Promise<DataFreshness>;
}

/**
 * GET /api/v1/watchlist (WAL-54): every watch-only package with the posture of its latest
 * release — the fleet view of "packages we monitor but do not fetch". Per-version detail is
 * GET /api/v1/packages/:name/posture.
 */
export function createWatchlistRouter(deps: WatchlistRouteDeps): Router {
  const router = Router();

  router.get("/", async (_req, res, next) => {
    try {
      const watched = await deps.listWatched();
      const entries = await Promise.all(
        watched.map(async (w) => {
          const p = await deps.getPosture(w.name);
          // The row was listed a moment ago; if it vanished the entry is simply omitted.
          if (!p) return null;
          return {
            name: w.name,
            display_name: w.display_name,
            vendor: w.vendor,
            latest_version: w.latest_version,
            latest_version_checked_at: w.latest_version_checked_at?.toISOString() ?? null,
            latest_version_error: w.latest_version_error,
            posture: {
              version: p.version,
              status: p.status,
              unknown_reasons: p.unknown_reasons,
              coverage: p.coverage,
              counts: p.counts,
              unfixed: p.unfixed,
              upgrade_to: p.upgrade_to,
            },
          };
        }),
      );
      res.json(
        WatchlistResponseSchema.parse({
          packages: entries.filter((e) => e !== null),
          data_freshness: await deps.getDataFreshness(),
          disclaimer: VULN_DISCLAIMER,
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}
