import { Pool } from "pg";
import { log } from "../../common/log.js";
import { NvdClient } from "./nvd-client.js";
import { incrementalNvdSync } from "./nvd-sync.js";
import { kevSync } from "./kev-sync.js";
import { osvSyncAll } from "./osv-sync.js";
import { enrichMissingCvss } from "./cvss-enrich.js";
import { VulnSyncImpls } from "./index.js";
import { withVulnSyncLock } from "./lock.js";

/**
 * Real vuln-sync implementations wired to the pool + live upstream clients.
 * Injected into the internal/admin routers; tests substitute fixture-backed fakes.
 */
export function createVulnSyncImpls(pool: Pool): VulnSyncImpls {
  return {
    nvd: () =>
      withVulnSyncLock(pool, "nvd", async () => {
        const nvd = new NvdClient({
          logger: { info: (m) => log.info(m), warn: (m) => log.warn(m) },
        });
        const counts = await incrementalNvdSync(pool, nvd, { log: (m) => log.info(m) });
        return { ...counts };
      }),
    kev: () =>
      withVulnSyncLock(pool, "kev", async () => {
        const r = await kevSync(pool);
        return { ...r };
      }),
    osv: () =>
      withVulnSyncLock(pool, "osv", async () => {
        const r = await osvSyncAll(pool);
        return { ...r };
      }),
    // Shares the "nvd" lock: it is NVD traffic, and must not race NVD ingestion
    // rewriting the same cves rows.
    cvss: () =>
      withVulnSyncLock(pool, "nvd", async () => {
        const nvd = new NvdClient({
          logger: { info: (m) => log.info(m), warn: (m) => log.warn(m) },
        });
        const r = await enrichMissingCvss(pool, nvd, { log: (m) => log.info(m) });
        return {
          candidates: r.candidates,
          fetched: r.fetched,
          updated: r.updated,
          not_found: r.not_found,
          no_metrics: r.no_metrics,
          errors: r.errors,
        };
      }),
  };
}
