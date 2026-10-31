import { Router } from "express";
import { withBase } from "../common/base-path.js";
import type { PackageRow, SyncJobRow } from "../types/db.js";
import type { WatchedPackageRow } from "../db/queries/packages.js";
import type { DataFreshness, VulnQueryResult } from "../services/vuln-query.js";
import type { VulnSyncStatus } from "../db/queries/vuln-sync-state.js";
import {
  escHtml,
  loadPackageGroups,
  renderDashboardPage,
  renderPackageDetailPage,
  renderViewerHtml,
  type PackageDetailLoaderDeps,
  type VersionVulnBadge,
} from "./admin.js";
import {
  autocompleteScript,
  renderLookupForm,
  renderResult,
  renderSourceChips,
  renderWatchedPage,
  type WatchedPostureSummary,
  RESULT_FILTER_SCRIPT,
  SOURCE_CHIPS_SCRIPT,
  VULN_VIEW_CSS,
} from "./admin-vulns.js";

/**
 * Everything the view-only pages read. Deliberately all reads: this router is handed no sync,
 * delete, enable/disable, waiver or suppression capability, so it cannot grow an action by
 * accident -- adding one means widening this interface in plain sight.
 */
export interface CatalogRouteDeps extends PackageDetailLoaderDeps {
  listConfiguredPackages: () => string[];
  /** Enabled packages only, the same set GET /api/v1/packages lists. */
  listEnabledPackages: () => Promise<PackageRow[]>;
  getPackage: (name: string) => Promise<PackageRow | null>;
  listJobs: (opts: { packageName?: string; limit?: number }) => Promise<SyncJobRow[]>;
  getPackageVulnBadges: (
    name: string,
  ) => Promise<{ tracked: boolean; byVersion: Record<string, VersionVulnBadge> }>;
  queryVulns: (product: string, version?: string) => Promise<VulnQueryResult>;
  getDataFreshness: () => Promise<DataFreshness>;
  getSyncStatus: () => Promise<VulnSyncStatus>;
  /** Watch-only packages (WAL-54): tracked for CVEs, never served. */
  listWatchedPackages: () => Promise<WatchedPackageRow[]>;
  /** Posture at a watched package's latest version. */
  getWatchedPosture: (name: string) => Promise<WatchedPostureSummary | null>;
}

function queryString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

/**
 * Unauthenticated, read-only HTML pages for people who need to see what walrus serves but are
 * not operators: the package catalogue and the vulnerability lookup. They render through the
 * same functions as the admin pages (mode "viewer"), so the two views cannot drift apart.
 *
 * Mounted on the public tier. A future `package-viewers` role goes in front of this router as
 * one middleware; nothing in here needs to change for that.
 */
export function createCatalogRouter(deps: CatalogRouteDeps, basePath: string): Router {
  const router = Router();

  // A package is viewable when it is configured AND enabled -- the rule GET /api/v1/packages
  // applies. A disabled package is therefore a 404, not a page that admits it exists.
  async function enabledConfiguredNames(): Promise<{
    names: string[];
    rows: Map<string, PackageRow>;
  }> {
    const configured = new Set(deps.listConfiguredPackages());
    const rows = new Map(
      (await deps.listEnabledPackages())
        .filter((p) => configured.has(p.name))
        .map((p) => [p.name, p]),
    );
    return { names: [...rows.keys()].sort((a, b) => a.localeCompare(b)), rows };
  }

  router.get("/packages", async (_req, res, next) => {
    try {
      const [{ names, rows }, recentJobs] = await Promise.all([
        enabledConfiguredNames(),
        deps.listJobs({ limit: 200 }),
      ]);
      const lastJobByPackage = new Map<string, SyncJobRow>();
      for (const job of recentJobs) {
        if (!lastJobByPackage.has(job.package_name)) lastJobByPackage.set(job.package_name, job);
      }
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderDashboardPage(names, rows, lastJobByPackage, new Map(), basePath, "viewer"));
    } catch (err) {
      next(err);
    }
  });

  router.get("/packages/:name", async (req, res, next) => {
    try {
      const packageName = req.params.name;
      const pkg = deps.listConfiguredPackages().includes(packageName)
        ? await deps.getPackage(packageName)
        : null;
      if (!pkg || !pkg.enabled) {
        res.status(404).setHeader("Content-Type", "text/html; charset=utf-8");
        res.send(
          renderViewerHtml(
            "Not Found",
            "packages",
            `<p>Package not found: ${escHtml(packageName)}</p>
             <p><a href="${withBase(basePath, "/packages")}">← Back to packages</a></p>`,
            basePath,
          ),
        );
        return;
      }

      const [recentJobs, groups, vulnBadges] = await Promise.all([
        deps.listJobs({ packageName, limit: 1 }),
        loadPackageGroups(deps, packageName),
        deps.getPackageVulnBadges(packageName),
      ]);

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(
        renderPackageDetailPage(
          packageName,
          pkg,
          recentJobs[0] ?? null,
          groups,
          vulnBadges,
          null,
          basePath,
          "viewer",
        ),
      );
    } catch (err) {
      next(err);
    }
  });

  router.get("/watched", async (_req, res, next) => {
    try {
      const watched = await deps.listWatchedPackages();
      const postures = new Map<string, WatchedPostureSummary>();
      await Promise.all(
        watched.map(async (w) => {
          const p = await deps.getWatchedPosture(w.name);
          if (p) postures.set(w.name, p);
        }),
      );
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderWatchedPage(watched, basePath, postures, "viewer"));
    } catch (err) {
      next(err);
    }
  });

  router.get("/vulns", async (req, res, next) => {
    try {
      const product = queryString(req.query.product);
      const version = queryString(req.query.version);

      const [freshness, syncStatus, result] = await Promise.all([
        deps.getDataFreshness(),
        deps.getSyncStatus(),
        product ? deps.queryVulns(product, version) : Promise.resolve(null),
      ]);

      let hasPackagePage = false;
      if (result?.match.resolved && result.match.product_slug) {
        hasPackagePage = (await enabledConfiguredNames()).rows.has(result.match.product_slug);
      }

      const body = `
    <h1>Vulnerabilities</h1>
    <p class="meta">Known CVEs for a product and version, and whether they block a download.</p>
    ${renderLookupForm(withBase(basePath, "/vulns"), product ?? "", version ?? "")}
    <div id="results-anchor">${
      result
        ? renderResult(result, basePath, "viewer", hasPackagePage)
        : `<p class="empty">Enter a product to look up known CVEs.</p>`
    }</div>
    <div class="status-strip"><div class="status-row">
      <strong>Data sources</strong>
      <span class="src-chips">${renderSourceChips(freshness, syncStatus)}</span>
    </div></div>`;

      const scripts = `${SOURCE_CHIPS_SCRIPT}\n${autocompleteScript(basePath)}\n${RESULT_FILTER_SCRIPT}`;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(
        renderViewerHtml(
          "Vulnerabilities",
          "vulns",
          body,
          basePath,
          scripts,
          `<style>${VULN_VIEW_CSS}</style>`,
        ),
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}
