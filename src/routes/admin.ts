import { Router } from "express";
import { buildArtifactPath } from "../storage/types.js";
import { ArtifactRow, PackageRow, SyncJobRow, VersionRow } from "../types/db.js";
import { FailedArtifactRow, PendingArtifactRow } from "../db/queries/artifacts.js";
import { ArtifactSummary, JobDetail } from "../db/queries/sync-jobs.js";
import { DownloadResult } from "../services/download-service.js";
import { SyncRunOptions, SyncRunResult } from "../services/sync-service.js";
import TOML from "@iarna/toml";
import { getStrategy, DiscoveredVersion } from "../discovery/index.js";
import { PackageConfigSchema, PackageConfig } from "../types/package-config.js";
import { sortVersionsDesc } from "../common/version-utils.js";

interface VersionDetail {
  version: string;
  versionId: number;
  isLts: boolean;
  artifacts: ArtifactRow[];
}

interface GroupDetail {
  name: string;
  versions: VersionDetail[];
}

export interface AdminRouteDeps {
  listConfiguredPackages: () => string[];
  getConfiguredPackageMeta: () => Array<{ name: string; display_name: string; vendor: string }>;
  runSync: (
    packageName: string,
    opts: { dryRun: boolean; triggerType: "admin" },
  ) => Promise<SyncRunResult>;
  runSyncAll: (opts: {
    dryRun: boolean;
    triggerType: "admin";
  }) => Promise<Array<{ package: string; result: SyncRunResult }>>;
  startSyncAsync: (packageName: string, opts: { triggerType: "admin" }) => Promise<number>;
  getArtifactByPackageVersionPlatform: (
    packageName: string,
    version: string,
    os: string,
    arch: string,
  ) => Promise<{ artifact: ArtifactRow; version: string } | null>;
  redownloadArtifact: (
    artifact: ArtifactRow,
    packageName: string,
    version: string,
  ) => Promise<DownloadResult>;
  listArtifactsByPackageVersion: (
    packageName: string,
    version: string,
    platform?: { os: string; arch: string },
  ) => Promise<ArtifactRow[]>;
  removeArtifact: (artifact: ArtifactRow) => Promise<void>;
  listFailedArtifacts: (opts: {
    packageName?: string;
    limit?: number;
  }) => Promise<FailedArtifactRow[]>;
  listPendingArtifacts: (opts: {
    packageName?: string;
    limit?: number;
  }) => Promise<PendingArtifactRow[]>;
  listJobs: (opts: {
    packageName?: string;
    status?: SyncJobRow["status"];
    limit?: number;
  }) => Promise<SyncJobRow[]>;
  getJob: (id: number) => Promise<JobDetail | null>;
  setPackageEnabled: (packageName: string, enabled: boolean) => Promise<boolean>;
  removeVersionGroup: (
    packageName: string,
    group: string,
  ) => Promise<{ versions: number; artifacts: number }>;
  removeAllVersionGroups: (packageName: string) => Promise<{ versions: number; artifacts: number }>;
  isPackageEnabled: (packageName: string) => Promise<boolean | null>;
  listAllPackages: () => Promise<PackageRow[]>;
  listVersionGroupNamesForPackage: (packageName: string) => Promise<string[]>;
  listVersionsInGroup: (packageName: string, group: string) => Promise<VersionRow[]>;
  listArtifactsForVersionId: (versionId: number) => Promise<ArtifactRow[]>;
  getTomlSource: (name: string) => string | null;
  /**
   * Per-version CVE summary for the package detail badges (plan §6). Backed by the
   * same cross-reference service as GET /api/v1/packages/:name/vulns — no duplicate SQL.
   */
  getPackageVulnBadges: (
    name: string,
  ) => Promise<{ tracked: boolean; byVersion: Record<string, VulnBadgeCounts> }>;
}

export interface VulnBadgeCounts {
  total: number;
  critical: number;
  high: number;
  kev: number;
}

export function createAdminRouter(deps: AdminRouteDeps): Router {
  const router = Router();

  router.post("/sync/:package", async (req, res, next) => {
    try {
      const packageName = req.params.package;
      if (!deps.listConfiguredPackages().includes(packageName)) {
        res.status(404).json({ error: `Unknown package: ${packageName}` });
        return;
      }

      const enabled = await deps.isPackageEnabled(packageName);
      if (enabled === false) {
        res.status(409).json({ error: `Package '${packageName}' is disabled` });
        return;
      }

      const dryRun = parseBoolean(req.query.dry_run);
      if (dryRun) {
        const result = await deps.runSync(packageName, { dryRun: true, triggerType: "admin" });
        res.json({ dry_run: true, package: packageName, result });
        return;
      }

      const jobId = await deps.startSyncAsync(packageName, { triggerType: "admin" });
      res.status(202).json({
        package: packageName,
        job_id: jobId,
        status_url: `/admin/v1/jobs/${jobId}`,
      });
    } catch (err) {
      next(err);
    }
  });

  router.post("/sync", async (req, res, next) => {
    try {
      const dryRun = parseBoolean(req.query.dry_run);
      if (dryRun) {
        const results = await deps.runSyncAll({ dryRun: true, triggerType: "admin" });
        res.json({
          dry_run: true,
          jobs: results.map((entry) => ({ package: entry.package, result: entry.result })),
        });
        return;
      }

      const packages = deps.listConfiguredPackages();
      const jobs: Array<{ package: string; job_id: number; status_url: string }> = [];
      for (const packageName of packages) {
        const enabled = await deps.isPackageEnabled(packageName);
        if (enabled === false) continue;
        const jobId = await deps.startSyncAsync(packageName, { triggerType: "admin" });
        jobs.push({ package: packageName, job_id: jobId, status_url: `/admin/v1/jobs/${jobId}` });
      }
      res.status(202).json({ jobs });
    } catch (err) {
      next(err);
    }
  });

  router.post("/redownload/:package/:version/:os/:arch", async (req, res, next) => {
    try {
      const packageName = req.params.package;
      const version = req.params.version;
      const os = req.params.os;
      const arch = req.params.arch;

      const resolved = await deps.getArtifactByPackageVersionPlatform(
        packageName,
        version,
        os,
        arch,
      );
      if (!resolved) {
        res.status(404).json({ error: "Artifact not found" });
        return;
      }

      const result = await deps.redownloadArtifact(
        resolved.artifact,
        packageName,
        resolved.version,
      );
      res.status(202).json({
        artifact_id: resolved.artifact.id,
        status: result.status,
        message: "Re-download finished",
      });
    } catch (err) {
      next(err);
    }
  });

  router.delete("/artifacts/:package/:version", async (req, res, next) => {
    try {
      const packageName = req.params.package;
      const version = req.params.version;
      const os = optionalString(req.query.os);
      const arch = optionalString(req.query.arch);

      if ((os && !arch) || (!os && arch)) {
        res.status(400).json({ error: "Both os and arch are required when filtering a platform" });
        return;
      }

      const artifacts = await deps.listArtifactsByPackageVersion(
        packageName,
        version,
        os && arch ? { os, arch } : undefined,
      );
      if (artifacts.length === 0) {
        res.status(404).json({ error: "No artifacts found" });
        return;
      }

      for (const artifact of artifacts) {
        await deps.removeArtifact(artifact);
      }

      res.json({ removed: artifacts.length, message: `Removed ${artifacts.length} artifacts` });
    } catch (err) {
      next(err);
    }
  });

  router.delete("/groups/:package", async (req, res, next) => {
    try {
      const packageName = req.params.package;

      const { versions, artifacts } = await deps.removeAllVersionGroups(packageName);
      if (versions === 0) {
        res.status(404).json({ error: `No versions found for package ${packageName}` });
        return;
      }

      res.json({
        package: packageName,
        versions_deleted: versions,
        artifacts_deleted: artifacts,
      });
    } catch (err) {
      next(err);
    }
  });

  router.delete("/groups/:package/:group", async (req, res, next) => {
    try {
      const packageName = req.params.package;
      const group = req.params.group;

      const { versions, artifacts } = await deps.removeVersionGroup(packageName, group);
      if (versions === 0) {
        res
          .status(404)
          .json({ error: `No versions found for group ${group} in package ${packageName}` });
        return;
      }

      res.json({
        package: packageName,
        group,
        versions_deleted: versions,
        artifacts_deleted: artifacts,
      });
    } catch (err) {
      next(err);
    }
  });

  router.get("/artifacts/failed", async (req, res, next) => {
    try {
      const packageName = optionalString(req.query.package);
      const limit = optionalInteger(req.query.limit);

      const artifacts = await deps.listFailedArtifacts({ packageName, limit });
      res.json({
        count: artifacts.length,
        artifacts: artifacts.map((a) => ({
          id: a.id,
          package: a.package_name,
          version: a.version,
          os: a.os,
          arch: a.arch,
          upstream_url: a.upstream_url,
          error_message: a.error_message,
          download_completed_at: a.download_completed_at,
          redownload: `/admin/v1/redownload/${a.package_name}/${a.version}/${a.os}/${a.arch}`,
        })),
      });
    } catch (err) {
      next(err);
    }
  });

  router.get("/artifacts/pending", async (req, res, next) => {
    try {
      const packageName = optionalString(req.query.package);
      const limit = optionalInteger(req.query.limit);

      const artifacts = await deps.listPendingArtifacts({ packageName, limit });
      res.json({
        count: artifacts.length,
        artifacts: artifacts.map((a) => ({
          id: a.id,
          package: a.package_name,
          version: a.version,
          os: a.os,
          arch: a.arch,
          upstream_url: a.upstream_url,
          cooling_off_until: a.cooling_off_until,
          created_at: a.created_at,
        })),
      });
    } catch (err) {
      next(err);
    }
  });

  router.get("/jobs", async (req, res, next) => {
    try {
      const packageName = optionalString(req.query.package);
      const status = optionalStatus(req.query.status);
      const wantsHtml = req.headers.accept?.includes("text/html");
      const limit = optionalInteger(req.query.limit) ?? (wantsHtml ? 50 : undefined);

      const jobs = await deps.listJobs({ packageName, status, limit });

      if (wantsHtml) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.send(renderJobsListPage(jobs));
        return;
      }

      res.json({ jobs });
    } catch (err) {
      next(err);
    }
  });

  router.get("/jobs/:id", async (req, res, next) => {
    try {
      const id = Number(req.params.id);
      if (!Number.isInteger(id) || id <= 0) {
        res.status(400).json({ error: "Invalid job id" });
        return;
      }

      const detail = await deps.getJob(id);
      if (!detail) {
        res.status(404).json({ error: "Job not found" });
        return;
      }

      if (req.headers.accept?.includes("text/html")) {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        res.send(renderJobStatusPage(detail));
      } else {
        res.json(buildJobResponse(detail));
      }
    } catch (err) {
      next(err);
    }
  });

  router.patch("/packages/:name", async (req, res, next) => {
    try {
      const packageName = req.params.name;
      const enabled = parseBodyBoolean((req.body as { enabled?: unknown } | undefined)?.enabled);

      if (enabled === undefined) {
        res.status(400).json({ error: "Body must include boolean field 'enabled'" });
        return;
      }

      const updated = await deps.setPackageEnabled(packageName, enabled);
      if (!updated) {
        res.status(404).json({ error: `Unknown package: ${packageName}` });
        return;
      }

      res.json({ package: packageName, enabled });
    } catch (err) {
      next(err);
    }
  });

  router.get("/", async (req, res, next) => {
    try {
      const configuredPackages = deps.listConfiguredPackages();
      const configMeta = new Map(deps.getConfiguredPackageMeta().map((m) => [m.name, m]));
      const [allDbPackages, recentJobs] = await Promise.all([
        deps.listAllPackages(),
        deps.listJobs({ limit: 200 }),
      ]);
      const packageMap = new Map(allDbPackages.map((p) => [p.name, p]));
      const lastJobByPackage = new Map<string, SyncJobRow>();
      for (const job of recentJobs) {
        if (!lastJobByPackage.has(job.package_name)) {
          lastJobByPackage.set(job.package_name, job);
        }
      }
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderDashboardPage(configuredPackages, packageMap, lastJobByPackage, configMeta));
    } catch (err) {
      next(err);
    }
  });

  router.get("/validate", (req, res, next) => {
    try {
      const configuredPackages = deps.listConfiguredPackages();
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderValidatePage(configuredPackages));
    } catch (err) {
      next(err);
    }
  });

  router.post("/validate-toml", async (req, res, next) => {
    try {
      const tomlStr = (req.body as { toml?: unknown })?.toml;
      if (typeof tomlStr !== "string") {
        res.status(400).json({ error: "Body must include string field 'toml'" });
        return;
      }

      type StepName = "toml_parse" | "schema_validate" | "discovery" | "spot_check" | "retention";
      interface StepResult {
        name: StepName;
        ok: boolean;
        error?: string;
        warning?: string;
        errors?: string[];
        strategy?: string;
        versionCount?: number;
        versionPreview?: string[];
        version?: string;
        platform?: string;
        url?: string;
        status?: number;
        contentLengthMB?: number;
        keptCount?: number;
        prunedCount?: number;
        keptPreview?: string[];
        prunedPreview?: string[];
      }

      const steps: StepResult[] = [];
      let overall = true;

      // Step 1: Parse TOML
      let parsed: unknown;
      try {
        parsed = TOML.parse(tomlStr);
        steps.push({ name: "toml_parse", ok: true });
      } catch (err) {
        steps.push({
          name: "toml_parse",
          ok: false,
          error: err instanceof Error ? err.message : String(err),
        });
        res.json({ steps, overall: false });
        return;
      }

      // Step 2: Schema validate
      const schemaResult = PackageConfigSchema.safeParse(parsed);
      if (!schemaResult.success) {
        const errors = schemaResult.error.issues.map(
          (i) => `${i.path.join(".") || "(root)"}: ${i.message}`,
        );
        steps.push({ name: "schema_validate", ok: false, errors });
        res.json({ steps, overall: false });
        return;
      }
      const config = schemaResult.data;
      steps.push({ name: "schema_validate", ok: true });

      // Step 3: Discovery
      let versions: DiscoveredVersion[];
      try {
        const strategy = getStrategy(config);
        const timeoutPromise = new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("Discovery timed out after 60s")), 60_000),
        );
        versions = await Promise.race([strategy.discoverVersions(config), timeoutPromise]);
        const preview = sortVersionsDesc(versions.map((v) => v.version)).slice(0, 6);
        steps.push({
          name: "discovery",
          ok: true,
          strategy: config.discovery.type,
          versionCount: versions.length,
          versionPreview: preview,
        });
      } catch (err) {
        steps.push({
          name: "discovery",
          ok: false,
          error: err instanceof Error ? err.message : String(err),
          strategy: config.discovery.type,
        });
        overall = false;
        res.json({ steps, overall });
        return;
      }

      // Step 4: Spot-check
      const newestVersion = versions[0];
      if (newestVersion) {
        const preferredKey = "linux/x86-64";
        const art =
          newestVersion.artifacts.get(preferredKey) ?? [...newestVersion.artifacts.values()][0];
        const platform = newestVersion.artifacts.has(preferredKey)
          ? preferredKey
          : ([...newestVersion.artifacts.keys()][0] ?? preferredKey);
        if (art) {
          try {
            const response = await fetch(art.url, {
              method: "HEAD",
              signal: AbortSignal.timeout(10_000),
            });
            const cl = response.headers.get("content-length");
            const contentLengthMB = cl
              ? parseFloat((parseInt(cl, 10) / 1_048_576).toFixed(1))
              : undefined;
            if (response.ok) {
              steps.push({
                name: "spot_check",
                ok: true,
                version: newestVersion.version,
                platform,
                url: art.url,
                status: response.status,
                contentLengthMB,
              });
            } else {
              steps.push({
                name: "spot_check",
                ok: true,
                warning: `HEAD returned ${response.status}`,
                version: newestVersion.version,
                platform,
                url: art.url,
                status: response.status,
                contentLengthMB,
              });
            }
          } catch (err) {
            steps.push({
              name: "spot_check",
              ok: true,
              warning: `HEAD request failed: ${err instanceof Error ? err.message : String(err)}`,
              version: newestVersion.version,
              platform,
              url: art.url,
            });
          }
        } else {
          steps.push({
            name: "spot_check",
            ok: true,
            warning: `No artifacts resolved for any platform on ${newestVersion.version}`,
          });
        }
      } else {
        steps.push({ name: "spot_check", ok: true, warning: "No versions discovered" });
      }

      // Step 5: Retention
      const plan = computeRetentionPlan(versions, config);
      steps.push({
        name: "retention",
        ok: true,
        keptCount: plan.kept.length,
        prunedCount: plan.pruned.length,
        keptPreview: plan.kept.slice(0, 5),
        prunedPreview: plan.pruned.slice(0, 5),
      });

      res.json({ steps, overall });
    } catch (err) {
      next(err);
    }
  });

  router.get("/packages/:name/toml-source", (req, res, next) => {
    try {
      const packageName = req.params.name;
      if (!deps.listConfiguredPackages().includes(packageName)) {
        res.status(404).json({ error: `Unknown package: ${packageName}` });
        return;
      }
      const source = deps.getTomlSource(packageName);
      if (source === null) {
        res.status(404).json({ error: "TOML source not available" });
        return;
      }
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.send(source);
    } catch (err) {
      next(err);
    }
  });

  router.get("/packages/:name", async (req, res, next) => {
    try {
      const packageName = req.params.name;
      if (!deps.listConfiguredPackages().includes(packageName)) {
        res.status(404).setHeader("Content-Type", "text/html; charset=utf-8");
        res.send(
          renderSharedHtml(
            "Not Found",
            "packages",
            `<p>Package not found: ${escHtml(packageName)}</p>`,
          ),
        );
        return;
      }

      const [allDbPackages, recentJobs, groupNames] = await Promise.all([
        deps.listAllPackages(),
        deps.listJobs({ packageName, limit: 1 }),
        deps.listVersionGroupNamesForPackage(packageName),
      ]);

      const pkg = allDbPackages.find((p) => p.name === packageName) ?? null;
      const lastJob = recentJobs[0] ?? null;

      const groups: GroupDetail[] = [];
      for (const groupName of groupNames) {
        const versions = await deps.listVersionsInGroup(packageName, groupName);
        const versionDetails: VersionDetail[] = [];
        for (const ver of versions) {
          const artifacts = await deps.listArtifactsForVersionId(ver.id);
          versionDetails.push({
            version: ver.version,
            versionId: ver.id,
            isLts: ver.is_lts,
            artifacts,
          });
        }
        groups.push({ name: groupName, versions: versionDetails });
      }

      const vulnBadges = await deps.getPackageVulnBadges(packageName);

      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderPackageDetailPage(packageName, pkg, lastJob, groups, vulnBadges));
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function coolingOffUntil(
  artifact: ArtifactSummary,
  coolingOffDays: number | undefined,
  threshold: string | null,
): Date | null {
  if (!coolingOffDays || artifact.status !== "pending" || threshold === null) return null;
  if (artifact.version_sort <= threshold) return null;
  const until = new Date(artifact.created_at.getTime() + coolingOffDays * 86_400_000);
  return until > new Date() ? until : null;
}

function buildJobResponse(detail: JobDetail): Record<string, unknown> {
  const { job, artifacts, elapsed_ms, cooling_off_days, cooling_off_threshold } = detail;
  const enrichedArtifacts = artifacts.map((a) => {
    const until = coolingOffUntil(a, cooling_off_days, cooling_off_threshold);
    return { ...a, cooling_off_until: until?.toISOString() ?? null };
  });
  const artifacts_cooling_off = enrichedArtifacts.filter(
    (a) => a.cooling_off_until !== null,
  ).length;
  return {
    id: job.id,
    package_name: job.package_name,
    trigger_type: job.trigger_type,
    status: job.status,
    versions_found: job.versions_found,
    artifacts_queued: job.artifacts_queued,
    artifacts_downloaded: job.artifacts_downloaded,
    artifacts_failed: job.artifacts_failed,
    artifacts_cooling_off,
    cooling_off_days: cooling_off_days ?? null,
    error_message: job.error_message,
    started_at: job.started_at,
    completed_at: job.completed_at,
    elapsed_ms,
    artifacts: enrichedArtifacts,
  };
}

function renderJobStatusPage(detail: JobDetail): string {
  const { job } = detail;
  const initialJson = JSON.stringify(buildJobResponse(detail)).replace(
    /<\/script>/gi,
    "<\\/script>",
  );
  const title = escHtml(`Job #${job.id} — ${job.package_name}`);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f5f5; color: #222; padding: 24px; }
    h1 { font-size: 1.4rem; margin-bottom: 16px; }
    .badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; }
    .badge-running { background: #dbeafe; color: #1d4ed8; }
    .badge-completed { background: #dcfce7; color: #15803d; }
    .badge-failed { background: #fee2e2; color: #b91c1c; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin: 16px 0; }
    .card { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px 20px; min-width: 130px; }
    .card-label { font-size: 0.75rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; }
    .card-value { font-size: 1.5rem; font-weight: 700; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; margin-top: 16px; }
    th { background: #f9fafb; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
    td { padding: 9px 12px; border-bottom: 1px solid #f3f4f6; font-size: 0.85rem; vertical-align: top; }
    tr:last-child td { border-bottom: none; }
    .status-available { color: #15803d; font-weight: 600; }
    .status-failed { color: #b91c1c; font-weight: 600; }
    .status-downloading { color: #1d4ed8; font-weight: 600; }
    .status-pending { color: #92400e; font-weight: 600; }
    .status-cooling-off { color: #6d28d9; font-weight: 600; }
    .row-available { background: #f0fdf4; }
    .row-failed { background: #fef2f2; }
    .row-downloading { background: #eff6ff; }
    .row-pending { background: #fffbeb; }
    .row-cooling-off { background: #f5f3ff; }
    .cooling-off-until { color: #6d28d9; font-size: 0.78rem; margin-top: 3px; }
    .error-msg { color: #b91c1c; font-size: 0.8rem; margin-top: 3px; }
    #last-updated { font-size: 0.75rem; color: #9ca3af; margin-top: 12px; }
  </style>
</head>
<body>
  <h1 id="page-title">${title}</h1>
  <div id="status-badge"></div>
  <div class="cards" id="cards"></div>
  <div id="artifacts-section"></div>
  <div id="last-updated"></div>

  <script>
    const INITIAL = ${initialJson};
    let pollTimer = null;

    function esc(s) {
      if (s == null) return '';
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function fmtElapsed(ms) {
      if (ms < 1000) return ms + 'ms';
      if (ms < 60000) return (ms / 1000).toFixed(1) + 's';
      return Math.floor(ms / 60000) + 'm ' + Math.floor((ms % 60000) / 1000) + 's';
    }

    function render(data) {
      const badge = document.getElementById('status-badge');
      badge.innerHTML = '<span class="badge badge-' + esc(data.status) + '">' + esc(data.status) + '</span>';

      const cards = document.getElementById('cards');
      const cardDefs = [
        ['Versions Found', data.versions_found],
        ['Artifacts Queued', data.artifacts_queued],
        ['Downloaded', data.artifacts_downloaded],
        ['Failed', data.artifacts_failed],
      ];
      if (data.cooling_off_days != null) {
        cardDefs.push(['Cooling Off (' + data.cooling_off_days + 'd)', data.artifacts_cooling_off]);
      }
      cardDefs.push(['Elapsed', fmtElapsed(data.elapsed_ms)]);
      cards.innerHTML = cardDefs.map(([label, val]) =>
        '<div class="card"><div class="card-label">' + esc(label) + '</div><div class="card-value">' + esc(val) + '</div></div>'
      ).join('');

      const arts = data.artifacts || [];
      const section = document.getElementById('artifacts-section');
      if (arts.length === 0) {
        section.innerHTML = '<p style="margin-top:16px;color:#6b7280;font-size:0.85rem">No artifact detail yet.</p>';
      } else {
        const rows = arts.map(a => {
          const isCoolingOff = a.cooling_off_until != null;
          const rowClass = isCoolingOff ? 'cooling-off' : a.status;
          const displayStatus = isCoolingOff ? 'cooling-off' : a.status;
          const errHtml = a.error_message ? '<div class="error-msg">' + esc(a.error_message) + '</div>' : '';
          const coolingHtml = isCoolingOff
            ? '<div class="cooling-off-until">available ' + esc(new Date(a.cooling_off_until).toLocaleString()) + '</div>'
            : '';
          return '<tr class="row-' + esc(rowClass) + '">'
            + '<td>' + esc(a.version) + '</td>'
            + '<td>' + esc(a.os) + '/' + esc(a.arch) + '</td>'
            + '<td>' + esc(a.filename) + '</td>'
            + '<td><span class="status-' + esc(displayStatus) + '">' + esc(displayStatus) + '</span>' + errHtml + coolingHtml + '</td>'
            + '</tr>';
        }).join('');
        section.innerHTML = '<table><thead><tr><th>Version</th><th>Platform</th><th>Filename</th><th>Status</th></tr></thead><tbody>' + rows + '</tbody></table>';
      }

      document.getElementById('last-updated').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
    }

    async function poll() {
      try {
        const res = await fetch(window.location.href, { headers: { Accept: 'application/json' } });
        if (!res.ok) return;
        const data = await res.json();
        render(data);
        if (data.status === 'completed' || data.status === 'failed') {
          clearInterval(pollTimer);
          pollTimer = null;
        }
      } catch (_) {}
    }

    render(INITIAL);
    if (INITIAL.status !== 'completed' && INITIAL.status !== 'failed') {
      pollTimer = setInterval(poll, 2000);
    }
  </script>
</body>
</html>`;
}

function fmtAge(date: Date): string {
  const ms = Date.now() - date.getTime();
  if (ms < 0 || ms < 60_000) return "just now";
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  if (ms < 86_400_000) return `${Math.floor(ms / 3_600_000)}h ago`;
  return `${Math.floor(ms / 86_400_000)}d ago`;
}

function fmtMs(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60_000)}m ${Math.floor((ms % 60_000) / 1000)}s`;
}

export function renderSharedHtml(
  title: string,
  activeNav: "packages" | "jobs" | "validate" | "vulns",
  body: string,
  scripts = "",
  rawTail = "",
): string {
  const e = escHtml;
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${e(title)} — Walrus Admin</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f5f5; color: #222; }
    .wrap { max-width: 1100px; margin: 0 auto; padding: 24px; }
    h1 { font-size: 1.4rem; margin-bottom: 16px; }
    h2 { font-size: 1rem; font-weight: 700; }
    a { color: #1d4ed8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .nav { display: flex; align-items: center; gap: 24px; background: #fff; border-bottom: 1px solid #e5e7eb; padding: 12px 24px; margin-bottom: 24px; }
    .nav .brand { font-weight: 800; font-size: 1.05rem; color: #111; }
    .nav a { font-size: 0.9rem; color: #6b7280; text-decoration: none; }
    .nav a:hover { color: #111; }
    .nav a.active { color: #111; font-weight: 700; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
    .badge-running  { background: #dbeafe; color: #1d4ed8; }
    .badge-completed { background: #dcfce7; color: #15803d; }
    .badge-failed   { background: #fee2e2; color: #b91c1c; }
    .badge-enabled  { background: #dcfce7; color: #15803d; }
    .badge-disabled { background: #f3f4f6; color: #6b7280; }
    .badge-lts      { background: #ede9fe; color: #6d28d9; }
    .badge-vuln-crit { background: #fee2e2; color: #b91c1c; }
    .badge-vuln-high { background: #fef3c7; color: #92400e; }
    .badge-vuln-none { background: #f3f4f6; color: #6b7280; }
    .badge-kev      { background: #7f1d1d; color: #fff; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; margin-top: 12px; }
    th { background: #f9fafb; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; padding: 9px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
    td { padding: 8px 12px; border-bottom: 1px solid #f3f4f6; font-size: 0.85rem; vertical-align: middle; }
    tr:last-child td { border-bottom: none; }
    .btn { display: inline-block; padding: 5px 12px; border-radius: 6px; font-size: 0.8rem; font-weight: 600; cursor: pointer; border: none; font-family: inherit; }
    .btn-sm { padding: 3px 8px; font-size: 0.75rem; }
    .btn-primary   { background: #1d4ed8; color: #fff; }
    .btn-primary:hover { background: #1e40af; }
    .btn-secondary { background: #e5e7eb; color: #374151; }
    .btn-secondary:hover { background: #d1d5db; }
    .btn-danger    { background: #fee2e2; color: #b91c1c; }
    .btn-danger:hover { background: #fecaca; }
    .status-available   { color: #15803d; font-weight: 600; }
    .status-failed      { color: #b91c1c; font-weight: 600; }
    .status-downloading { color: #1d4ed8; font-weight: 600; }
    .status-pending     { color: #92400e; font-weight: 600; }
    .status-removed     { color: #9ca3af; }
    .group-section { margin-top: 28px; }
    .group-header { display: flex; align-items: center; gap: 10px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; }
    .meta { font-size: 0.82rem; color: #6b7280; margin-bottom: 16px; }
    .meta strong { color: #222; }
    .actions { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-bottom: 20px; }
    .empty { color: #9ca3af; font-size: 0.85rem; margin-top: 16px; }
    #msg { min-height: 1.2em; margin-top: 8px; font-size: 0.82rem; color: #6b7280; }
  </style>
</head>
<body>
  <nav class="nav">
    <span class="brand">Walrus</span>
    <a href="/admin/v1/"${activeNav === "packages" ? ' class="active"' : ""}>Packages</a>
    <a href="/admin/v1/jobs"${activeNav === "jobs" ? ' class="active"' : ""}>Jobs</a>
    <a href="/admin/v1/validate"${activeNav === "validate" ? ' class="active"' : ""}>Validate TOML</a>
    <a href="/admin/v1/vulns"${activeNav === "vulns" ? ' class="active"' : ""}>Vulnerabilities</a>
    <a href="/api">API Docs</a>
    <a href="/health">Health</a>
  </nav>
  <div class="wrap">
    ${body}
  </div>
<script>
${scripts}
</script>${rawTail}
</body>
</html>`;
}

function computeRetentionPlan(
  versions: DiscoveredVersion[],
  config: PackageConfig,
): { kept: string[]; pruned: string[] } {
  const byGroup = new Map<string, string[]>();
  for (const v of versions) {
    if (!byGroup.has(v.versionGroup)) byGroup.set(v.versionGroup, []);
    byGroup.get(v.versionGroup)!.push(v.version);
  }
  const sortedGroups = sortVersionsDesc([...byGroup.keys()]);
  const kept: string[] = [];
  const pruned: string[] = [];
  const limit = config.retention.versions_per_group;
  const groupsToKeep = config.retention.groups_to_keep;
  for (let i = 0; i < sortedGroups.length; i++) {
    const group = sortedGroups[i];
    const sorted = sortVersionsDesc(byGroup.get(group)!);
    if (groupsToKeep !== undefined && i >= groupsToKeep) {
      pruned.push(...sorted);
    } else {
      kept.push(...sorted.slice(0, limit));
      pruned.push(...sorted.slice(limit));
    }
  }
  return { kept, pruned };
}

function renderValidatePage(configuredPackages: string[]): string {
  const esc = escHtml;
  const packageOptions = configuredPackages
    .map((p) => `<option value="${esc(p)}">${esc(p)}</option>`)
    .join("");

  const body = `
    <h1>Validate TOML Config</h1>
    <p class="meta" style="margin-bottom:16px">Paste a package TOML config to validate it without writing to disk.</p>
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px">
      <label style="font-size:0.85rem;font-weight:600;color:#374151;white-space:nowrap">Load existing:</label>
      <select id="pkg-select" style="padding:4px 8px;border:1px solid #d1d5db;border-radius:6px;font-size:0.85rem;font-family:inherit;background:#fff">
        <option value="">— select a package —</option>
        ${packageOptions}
      </select>
      <span id="load-status" style="font-size:0.8rem;color:#9ca3af"></span>
    </div>
    <div id="editor-container" style="border:1px solid #d1d5db;border-radius:6px;overflow:hidden;min-height:320px;background:#fff;font-size:0.875rem;line-height:1.5;margin-bottom:12px"></div>
    <div style="display:flex;gap:10px;align-items:center">
      <button id="validate-btn" class="btn btn-primary" onclick="doValidate()">Validate</button>
      <span id="validate-status" style="font-size:0.82rem;color:#6b7280"></span>
    </div>
    <div id="results" style="margin-top:20px;display:none"></div>`;

  const rawTail = `
<script src="/static/editor-bundle.js"></script>
<script>
  const { basicSetup, EditorView, StreamLanguage, toml } = window.WalrusEditor;

  const editor = new EditorView({
    extensions: [basicSetup, StreamLanguage.define(toml)],
    parent: document.getElementById("editor-container"),
  });

  function getEditorContent() {
    return editor.state.doc.toString();
  }

  function setEditorContent(text) {
    editor.dispatch({ changes: { from: 0, to: editor.state.doc.length, insert: text } });
  }

  document.getElementById("pkg-select").addEventListener("change", async (e) => {
    const name = e.target.value;
    if (!name) return;
    const statusEl = document.getElementById("load-status");
    statusEl.textContent = "Loading…";
    try {
      const r = await fetch("/admin/v1/packages/" + encodeURIComponent(name) + "/toml-source");
      if (!r.ok) { statusEl.textContent = "Failed to load"; return; }
      const text = await r.text();
      setEditorContent(text);
      statusEl.textContent = "Loaded";
      setTimeout(() => { statusEl.textContent = ""; }, 2000);
    } catch (err) {
      statusEl.textContent = "Error: " + err.message;
    }
  });

  function esc(s) {
    if (s == null) return "";
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }

  function stepLabel(name) {
    return { toml_parse: "TOML Parse", schema_validate: "Schema Validate", discovery: "Discovery", spot_check: "Spot Check", retention: "Retention" }[name] || name;
  }

  function renderStep(step) {
    const icon = step.ok ? (step.warning ? "⚠" : "✓") : "✗";
    const badgeColor = step.ok ? (step.warning ? "#92400e;background:#fef9c3" : "#15803d;background:#dcfce7") : "#b91c1c;background:#fee2e2";
    let details = "";

    if (step.error) {
      details += '<p style="margin-top:6px;color:#b91c1c;font-size:0.82rem;font-family:monospace;white-space:pre-wrap">' + esc(step.error) + "</p>";
    }
    if (step.warning) {
      details += '<p style="margin-top:6px;color:#92400e;font-size:0.82rem">⚠ ' + esc(step.warning) + "</p>";
    }
    if (step.errors && step.errors.length) {
      details += '<ul style="margin-top:6px;padding-left:18px;font-size:0.82rem;color:#b91c1c">' + step.errors.map(e => "<li>" + esc(e) + "</li>").join("") + "</ul>";
    }
    if (step.strategy) {
      details += '<p style="margin-top:6px;font-size:0.82rem;color:#374151">Strategy: <code>' + esc(step.strategy) + "</code></p>";
    }
    if (step.versionCount != null) {
      details += '<p style="font-size:0.82rem;color:#374151">Found <strong>' + esc(step.versionCount) + '</strong> version(s)';
      if (step.versionPreview && step.versionPreview.length) {
        details += ': <code>' + step.versionPreview.map(esc).join(", ") + (step.versionCount > step.versionPreview.length ? ", …" : "") + "</code>";
      }
      details += "</p>";
    }
    if (step.url) {
      details += '<p style="margin-top:6px;font-size:0.82rem;color:#374151">Version: <code>' + esc(step.version) + "</code> · Platform: <code>" + esc(step.platform) + "</code></p>";
      details += '<p style="font-size:0.82rem;color:#6b7280;word-break:break-all">URL: ' + esc(step.url) + "</p>";
      if (step.status != null) {
        const sizeStr = step.contentLengthMB != null ? " · " + step.contentLengthMB + " MB" : "";
        details += '<p style="font-size:0.82rem;color:#374151">HTTP ' + esc(step.status) + sizeStr + "</p>";
      }
    }
    if (step.keptCount != null) {
      details += '<p style="margin-top:6px;font-size:0.82rem;color:#374151">Keep <strong>' + esc(step.keptCount) + '</strong> version(s), prune <strong>' + esc(step.prunedCount) + "</strong></p>";
      if (step.keptPreview && step.keptPreview.length) {
        details += '<p style="font-size:0.82rem;color:#15803d">Keep: <code>' + step.keptPreview.map(esc).join(", ") + (step.keptCount > step.keptPreview.length ? ", …" : "") + "</code></p>";
      }
      if (step.prunedPreview && step.prunedPreview.length) {
        details += '<p style="font-size:0.82rem;color:#9ca3af">Prune: <code>' + step.prunedPreview.map(esc).join(", ") + (step.prunedCount > step.prunedPreview.length ? ", …" : "") + "</code></p>";
      }
    }

    return '<div style="border:1px solid #e5e7eb;border-radius:8px;padding:12px 16px;background:#fff">'
      + '<div style="display:flex;align-items:center;gap:10px">'
      + '<span style="display:inline-block;padding:2px 10px;border-radius:12px;font-size:0.78rem;font-weight:700;color:' + badgeColor + '">' + icon + ' ' + esc(stepLabel(step.name)) + '</span>'
      + '</div>'
      + details
      + '</div>';
  }

  window.doValidate = async function() {
    const toml = getEditorContent().trim();
    if (!toml) { alert("Please enter TOML content to validate."); return; }
    const btn = document.getElementById("validate-btn");
    const statusEl = document.getElementById("validate-status");
    const resultsEl = document.getElementById("results");
    btn.disabled = true;
    btn.textContent = "Validating…";
    statusEl.textContent = "";
    resultsEl.style.display = "none";
    try {
      const r = await fetch("/admin/v1/validate-toml", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ toml }),
      });
      const data = await r.json();
      if (!r.ok) { statusEl.textContent = "Error: " + (data.error || r.status); return; }

      const overall = data.overall;
      const overallHtml = overall
        ? '<div style="padding:10px 16px;background:#dcfce7;border:1px solid #86efac;border-radius:8px;color:#15803d;font-weight:700;font-size:0.9rem">✓ All checks passed</div>'
        : '<div style="padding:10px 16px;background:#fee2e2;border:1px solid #fca5a5;border-radius:8px;color:#b91c1c;font-weight:700;font-size:0.9rem">✗ Validation failed</div>';

      resultsEl.innerHTML = overallHtml + '<div style="display:flex;flex-direction:column;gap:10px;margin-top:12px">' + data.steps.map(renderStep).join("") + '</div>';
      resultsEl.style.display = "block";
    } catch (err) {
      statusEl.textContent = "Request failed: " + err.message;
    } finally {
      btn.disabled = false;
      btn.textContent = "Validate";
    }
  };
</script>`;

  return renderSharedHtml("Validate TOML", "validate", body, "", rawTail);
}

function renderDashboardPage(
  configuredPackages: string[],
  packageMap: Map<string, PackageRow>,
  lastJobByPackage: Map<string, SyncJobRow>,
  configMeta: Map<string, { display_name: string; vendor: string }>,
): string {
  const esc = escHtml;

  const rows = configuredPackages
    .map((name) => {
      const pkg = packageMap.get(name);
      const meta = configMeta.get(name);
      const lastJob = lastJobByPackage.get(name);
      const displayName = pkg ? esc(pkg.display_name) : esc(meta?.display_name ?? name);
      const vendor = pkg ? esc(pkg.vendor) : esc(meta?.vendor ?? "—");
      const enabled = pkg?.enabled ?? true;
      const enabledBadge = `<span class="badge badge-${enabled ? "enabled" : "disabled"}">${enabled ? "enabled" : "disabled"}</span>`;
      const jobHtml = lastJob
        ? `<a href="/admin/v1/jobs/${lastJob.id}" class="badge badge-${esc(lastJob.status)}">${esc(lastJob.status)}</a> <span style="color:#9ca3af;font-size:0.78rem">${fmtAge(lastJob.started_at)}</span>`
        : `<span style="color:#9ca3af;font-size:0.78rem">never</span>`;
      const isRunning = lastJob?.status === "running";
      const syncBtn = isRunning
        ? `<span class="btn btn-sm btn-secondary" style="cursor:default;opacity:0.6">running…</span>`
        : `<button class="btn btn-sm btn-primary" onclick="syncPkg('${esc(name)}')">Sync</button>`;
      const toggleBtn = `<button class="btn btn-sm btn-secondary" onclick="toggleEnabled('${esc(name)}',${enabled})">${enabled ? "Disable" : "Enable"}</button>`;
      return `<tr>
        <td><a href="/admin/v1/packages/${esc(name)}">${displayName}</a></td>
        <td>${vendor}</td>
        <td>${enabledBadge}</td>
        <td>${jobHtml}</td>
        <td style="white-space:nowrap">${syncBtn} ${toggleBtn}</td>
      </tr>`;
    })
    .join("");

  const tableHtml =
    configuredPackages.length === 0
      ? `<p class="empty">No packages configured.</p>`
      : `<table>
        <thead><tr><th>Package</th><th>Vendor</th><th>Status</th><th>Last Sync</th><th>Actions</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;

  const hasRunning = [...lastJobByPackage.values()].some((j) => j.status === "running");

  const body = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
      <h1 style="margin-bottom:0">Packages</h1>
      <button class="btn btn-primary" onclick="syncAll()">Sync All</button>
    </div>
    ${tableHtml}
    <div id="msg"></div>`;

  const scripts = `
    async function syncPkg(name) {
      document.getElementById('msg').textContent = 'Starting sync for ' + name + '…';
      try {
        const r = await fetch('/admin/v1/sync/' + name, {method: 'POST'});
        const d = await r.json();
        if (r.ok) window.location = '/admin/v1/jobs/' + d.job_id;
        else document.getElementById('msg').textContent = 'Error: ' + (d.error || r.status);
      } catch(e) { document.getElementById('msg').textContent = 'Error: ' + e.message; }
    }
    async function syncAll() {
      if (!confirm('Sync all packages?')) return;
      document.getElementById('msg').textContent = 'Starting sync for all packages…';
      try {
        const r = await fetch('/admin/v1/sync', {method: 'POST'});
        if (r.ok) window.location = '/admin/v1/jobs';
        else { const d = await r.json(); document.getElementById('msg').textContent = 'Error: ' + (d.error || r.status); }
      } catch(e) { document.getElementById('msg').textContent = 'Error: ' + e.message; }
    }
    async function toggleEnabled(name, enabled) {
      if (!confirm((enabled ? 'Disable' : 'Enable') + ' ' + name + '?')) return;
      try {
        const r = await fetch('/admin/v1/packages/' + name, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({enabled: !enabled})
        });
        if (r.ok) location.reload();
        else { const d = await r.json(); alert('Error: ' + (d.error || r.status)); }
      } catch(e) { alert('Error: ' + e.message); }
    }
    ${hasRunning ? "setInterval(() => location.reload(), 5000);" : ""}`;

  return renderSharedHtml("Packages", "packages", body, scripts);
}

function renderPackageDetailPage(
  packageName: string,
  pkg: PackageRow | null,
  lastJob: SyncJobRow | null,
  groups: GroupDetail[],
  vulnBadges: { tracked: boolean; byVersion: Record<string, VulnBadgeCounts> },
): string {
  const esc = escHtml;
  const displayName = pkg ? esc(pkg.display_name) : esc(packageName);
  const vendor = pkg ? esc(pkg.vendor) : "—";
  const enabled = pkg?.enabled ?? true;
  const isRunning = lastJob?.status === "running";

  const lastSyncHtml = lastJob
    ? `Last sync: <a href="/admin/v1/jobs/${lastJob.id}"><span class="badge badge-${esc(lastJob.status)}">${esc(lastJob.status)}</span></a> ${fmtAge(lastJob.started_at)}`
    : "Never synced";

  const headerHtml = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
      <h1 style="margin-bottom:0">${displayName}</h1>
      <span class="badge badge-${enabled ? "enabled" : "disabled"}">${enabled ? "enabled" : "disabled"}</span>
    </div>
    <p class="meta">Vendor: <strong>${vendor}</strong>${
      pkg?.website
        ? ` · <a href="${esc(pkg.website)}" target="_blank" rel="noopener">${esc(pkg.website)}</a>`
        : ""
    } · ${lastSyncHtml}</p>
    <div class="actions">
      ${
        isRunning
          ? `<span class="btn btn-secondary" style="cursor:default;opacity:0.6">Sync running…</span>`
          : `<button class="btn btn-primary" onclick="syncPkg('${esc(packageName)}')">Sync Now</button>`
      }
      <button class="btn btn-secondary" onclick="toggleEnabled('${esc(packageName)}',${enabled})">${enabled ? "Disable" : "Enable"}</button>
      <button class="btn btn-danger" style="margin-left:auto" onclick="deleteAllGroups('${esc(packageName)}')">Delete All Data</button>
    </div>`;

  const groupsHtml =
    groups.length === 0
      ? `<p class="empty">No versions synced yet. Run a sync to discover versions.</p>`
      : groups.map((g) => renderGroupSection(packageName, g, vulnBadges)).join("");

  const body = `
    <div style="margin-bottom:16px"><a href="/admin/v1/">← Back to packages</a></div>
    ${headerHtml}
    <div id="msg"></div>
    ${groupsHtml}`;

  const scripts = `
    async function syncPkg(name) {
      document.getElementById('msg').textContent = 'Starting sync…';
      try {
        const r = await fetch('/admin/v1/sync/' + name, {method: 'POST'});
        const d = await r.json();
        if (r.ok) window.location = '/admin/v1/jobs/' + d.job_id;
        else document.getElementById('msg').textContent = 'Error: ' + (d.error || r.status);
      } catch(e) { document.getElementById('msg').textContent = 'Error: ' + e.message; }
    }
    async function toggleEnabled(name, enabled) {
      if (!confirm((enabled ? 'Disable' : 'Enable') + ' ' + name + '?')) return;
      try {
        const r = await fetch('/admin/v1/packages/' + name, {
          method: 'PATCH', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({enabled: !enabled})
        });
        if (r.ok) location.reload();
        else { const d = await r.json(); alert('Error: ' + (d.error || r.status)); }
      } catch(e) { alert('Error: ' + e.message); }
    }
    async function deleteGroup(pkg, group) {
      if (!confirm('Delete all versions in group "' + group + '" for ' + pkg + '? This cannot be undone.')) return;
      document.getElementById('msg').textContent = 'Deleting group ' + group + '…';
      try {
        const r = await fetch('/admin/v1/groups/' + pkg + '/' + encodeURIComponent(group), {method: 'DELETE'});
        if (r.ok) location.reload();
        else { const d = await r.json(); alert('Error: ' + (d.error || r.status)); }
      } catch(e) { alert('Error: ' + e.message); }
    }
    async function deleteAllGroups(pkg) {
      if (!confirm('Delete ALL versions and artifacts for ' + pkg + '? This cannot be undone.')) return;
      document.getElementById('msg').textContent = 'Deleting all data for ' + pkg + '…';
      try {
        const r = await fetch('/admin/v1/groups/' + pkg, {method: 'DELETE'});
        if (r.ok) location.reload();
        else { const d = await r.json(); alert('Error: ' + (d.error || r.status)); }
      } catch(e) { alert('Error: ' + e.message); }
    }
    async function redownload(pkg, version, os, arch) {
      if (!confirm('Re-download ' + version + ' ' + os + '/' + arch + '?')) return;
      document.getElementById('msg').textContent = 'Re-downloading…';
      try {
        const r = await fetch('/admin/v1/redownload/' + pkg + '/' + version + '/' + os + '/' + arch, {method: 'POST'});
        const d = await r.json();
        if (r.ok) { document.getElementById('msg').textContent = 'Done: ' + d.status; location.reload(); }
        else { alert('Error: ' + (d.error || r.status)); }
      } catch(e) { alert('Error: ' + e.message); }
    }`;

  return renderSharedHtml(displayName, "packages", body, scripts);
}

function renderVulnBadge(
  packageName: string,
  version: string,
  counts: VulnBadgeCounts | undefined,
): string {
  if (!counts || counts.total === 0) return "";
  const cls =
    counts.critical > 0 || counts.kev > 0
      ? "badge-vuln-crit"
      : counts.high > 0
        ? "badge-vuln-high"
        : "badge-vuln-none";
  const label = counts.kev > 0 ? `${counts.total} CVE · KEV` : `${counts.total} CVE`;
  const href = `/admin/v1/vulns?product=${encodeURIComponent(packageName)}&version=${encodeURIComponent(version)}`;
  return ` <a href="${href}" title="${counts.critical} critical, ${counts.high} high${counts.kev > 0 ? `, ${counts.kev} KEV` : ""}" class="badge ${cls}" style="text-decoration:none">${label}</a>`;
}

function renderGroupSection(
  packageName: string,
  g: GroupDetail,
  vulnBadges: { tracked: boolean; byVersion: Record<string, VulnBadgeCounts> },
): string {
  const esc = escHtml;
  const hasLts = g.versions.some((v) => v.isLts);
  const platforms = [
    ...new Set(g.versions.flatMap((v) => v.artifacts.map((a) => `${a.os}/${a.arch}`))),
  ].sort();

  const header = `
    <div class="group-header">
      <h2>${esc(g.name)}</h2>
      ${hasLts ? `<span class="badge badge-lts">LTS</span>` : ""}
      <button class="btn btn-sm btn-danger" style="margin-left:auto" onclick="deleteGroup('${esc(packageName)}','${esc(g.name)}')">Delete Group</button>
    </div>`;

  if (g.versions.length === 0) {
    return `<div class="group-section">${header}<p class="empty">No versions.</p></div>`;
  }

  const platHeaders = platforms.map((p) => `<th>${esc(p)}</th>`).join("");
  const rows = g.versions
    .map((v) => {
      const byPlatform = new Map(v.artifacts.map((a) => [`${a.os}/${a.arch}`, a]));
      const cells = platforms
        .map((p) => {
          const a = byPlatform.get(p);
          if (!a) return `<td style="color:#d1d5db">—</td>`;
          const icon: Record<string, string> = {
            available: "✓",
            failed: "✗",
            downloading: "↓",
            pending: "○",
            removed: "–",
          };
          const cls = `status-${a.status}`;
          const [os, arch] = p.split("/");
          const redownloadBtn =
            a.status === "failed" || a.status === "available"
              ? ` <button class="btn btn-sm btn-secondary" title="Re-download" onclick="redownload('${esc(packageName)}','${esc(v.version)}','${esc(os)}','${esc(arch)}')">↺</button>`
              : "";
          return `<td><span class="${cls}">${icon[a.status] ?? "?"} ${esc(a.status)}</span>${redownloadBtn}</td>`;
        })
        .join("");
      const badge = vulnBadges.tracked
        ? renderVulnBadge(packageName, v.version, vulnBadges.byVersion[v.version])
        : "";
      return `<tr><td><strong>${esc(v.version)}</strong>${badge}</td>${cells}</tr>`;
    })
    .join("");

  return `<div class="group-section">
    ${header}
    <table>
      <thead><tr><th>Version</th>${platHeaders}</tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;
}

function renderJobsListPage(jobs: SyncJobRow[]): string {
  const esc = escHtml;
  const rows = jobs
    .map((j) => {
      const elapsed = (j.completed_at ?? new Date()).getTime() - j.started_at.getTime();
      const failedCell =
        j.artifacts_failed > 0 ? `<span class="status-failed">${j.artifacts_failed}</span>` : "0";
      return `<tr>
        <td><a href="/admin/v1/jobs/${j.id}">#${j.id}</a></td>
        <td><a href="/admin/v1/packages/${esc(j.package_name)}">${esc(j.package_name)}</a></td>
        <td>${esc(j.trigger_type)}</td>
        <td><span class="badge badge-${esc(j.status)}">${esc(j.status)}</span></td>
        <td>${j.versions_found}</td>
        <td>${j.artifacts_downloaded}</td>
        <td>${failedCell}</td>
        <td style="color:#9ca3af;font-size:0.78rem;white-space:nowrap">${fmtAge(j.started_at)}</td>
        <td style="color:#9ca3af;font-size:0.78rem">${fmtMs(elapsed)}</td>
      </tr>`;
    })
    .join("");

  const tableHtml =
    jobs.length === 0
      ? `<p class="empty">No jobs found.</p>`
      : `<table>
        <thead><tr>
          <th>ID</th><th>Package</th><th>Trigger</th><th>Status</th>
          <th>Versions</th><th>Downloaded</th><th>Failed</th><th>Started</th><th>Elapsed</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>`;

  const hasRunning = jobs.some((j) => j.status === "running");

  const body = `
    <h1>Sync Jobs</h1>
    ${tableHtml}
    <div id="ts" style="font-size:0.75rem;color:#9ca3af;margin-top:12px"></div>`;

  const scripts = `
    document.getElementById('ts').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
    ${hasRunning ? "setInterval(() => location.reload(), 3000);" : ""}`;

  return renderSharedHtml("Sync Jobs", "jobs", body, scripts);
}

export function escHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function parseBoolean(value: unknown): boolean {
  const normalized = optionalString(value)?.toLowerCase();
  return normalized === "true" || normalized === "1";
}

function parseBodyBoolean(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  return undefined;
}

function optionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}

function optionalInteger(value: unknown): number | undefined {
  const str = optionalString(value);
  if (!str) return undefined;
  const parsed = Number(str);
  if (!Number.isInteger(parsed) || parsed <= 0) return undefined;
  return parsed;
}

function optionalStatus(value: unknown): SyncJobRow["status"] | undefined {
  const str = optionalString(value);
  if (str === "running" || str === "completed" || str === "failed") {
    return str;
  }
  return undefined;
}

export function buildRedownloadPath(
  packageName: string,
  version: string,
  artifact: Pick<ArtifactRow, "os" | "arch" | "filename">,
): string {
  return buildArtifactPath({
    packageName,
    version,
    os: artifact.os,
    arch: artifact.arch,
    filename: artifact.filename,
  });
}

// Re-export for use in main.ts
export type { SyncRunOptions };
