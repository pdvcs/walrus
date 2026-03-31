import { Router } from "express";
import { ArtifactRow, PackageRow, SyncJobRow, VersionRow } from "../types/db.js";
import { VersionGroupSummary } from "../db/queries/versions.js";
import {
  LatestArtifactResponseSchema,
  ListGroupsResponseSchema,
  ListPackagesResponseSchema,
  ListVersionsResponseSchema,
  SyncingResponseSchema,
} from "./schemas.js";

export interface PackagesRouteDeps {
  listEnabledPackages: () => Promise<PackageRow[]>;
  getPackage: (name: string) => Promise<PackageRow | null>;
  listVersionGroups: (packageName: string) => Promise<string[]>;
  listVersionGroupSummaries: (
    packageName: string,
    opts?: { os?: string; arch?: string },
  ) => Promise<VersionGroupSummary[]>;
  listVersions: (packageName: string, opts: { lts?: boolean }) => Promise<VersionRow[]>;
  getLatestVersionInGroup: (
    packageName: string,
    group: string,
    opts?: { os?: string; arch?: string },
  ) => Promise<VersionRow | null>;
  listArtifactsForVersion: (versionId: number) => Promise<ArtifactRow[]>;
  getRecentSyncJob: (packageName: string, withinMinutes: number) => Promise<SyncJobRow | null>;
  triggerOnDemandSync: (packageName: string) => Promise<void>;
}

export function createPackagesRouter(deps: PackagesRouteDeps): Router {
  const router = Router();

  router.get("/", async (_req, res, next) => {
    try {
      const packages = await deps.listEnabledPackages();
      res.json(
        ListPackagesResponseSchema.parse({
          packages: packages.map((pkg) => ({
            name: pkg.name,
            display_name: pkg.display_name,
            vendor: pkg.vendor,
            description: pkg.description,
            website: pkg.website,
          })),
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  router.get("/:name/groups", async (req, res, next) => {
    try {
      const packageName = req.params.name;
      const pkg = await deps.getPackage(packageName);
      if (!pkg || !pkg.enabled) {
        res.status(404).json({ error: `Unknown package: ${packageName}` });
        return;
      }

      const os = optionalString(req.query.os);
      const arch = optionalString(req.query.arch);
      const groups = await deps.listVersionGroupSummaries(packageName, { os, arch });
      res.json(ListGroupsResponseSchema.parse({ package: packageName, groups }));
    } catch (err) {
      next(err);
    }
  });

  router.get("/:name/versions", async (req, res, next) => {
    try {
      const packageName = req.params.name;
      const pkg = await deps.getPackage(packageName);
      if (!pkg || !pkg.enabled) {
        res.status(404).json({ error: `Unknown package: ${packageName}` });
        return;
      }

      const lts = parseOptionalBoolean(req.query.lts);
      const [versionGroups, versions] = await Promise.all([
        deps.listVersionGroups(packageName),
        deps.listVersions(packageName, lts === undefined ? {} : { lts }),
      ]);

      const versionsWithArtifacts = await Promise.all(
        versions.map(async (version) => {
          const artifacts = await deps.listArtifactsForVersion(version.id);
          return {
            version: version.version,
            version_group: version.version_group,
            is_lts: version.is_lts,
            platforms: artifacts.map((artifact) => ({
              os: artifact.os,
              arch: artifact.arch,
              status: artifact.status,
            })),
          };
        }),
      );

      res.json(
        ListVersionsResponseSchema.parse({
          package: packageName,
          version_groups: versionGroups,
          versions: versionsWithArtifacts,
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  router.get("/:name/versions/:group/latest", async (req, res, next) => {
    try {
      const packageName = req.params.name;
      const group = req.params.group;

      const pkg = await deps.getPackage(packageName);
      if (!pkg || !pkg.enabled) {
        res.status(404).json({ error: `Unknown package: ${packageName}` });
        return;
      }

      const os = optionalString(req.query.os);
      const arch = optionalString(req.query.arch);
      const version = await deps.getLatestVersionInGroup(packageName, group, { os, arch });
      if (!version) {
        const recent = await deps.getRecentSyncJob(packageName, 30);
        if (!recent) {
          deps.triggerOnDemandSync(packageName).catch(() => {
            // Best effort background trigger; response still instructs caller to retry.
          });
          res
            .status(202)
            .set("Retry-After", "30")
            .json(
              SyncingResponseSchema.parse({
                status: "syncing",
                message: "Version not yet available, retry shortly",
              }),
            );
          return;
        }

        res.status(404).json({ error: `No version found for group ${group}` });
        return;
      }

      const artifacts = await deps.listArtifactsForVersion(version.id);
      const artifact = selectArtifact(artifacts, os, arch);
      if (!artifact) {
        res.status(404).json({ error: "No matching artifact for requested platform" });
        return;
      }

      res.json(
        LatestArtifactResponseSchema.parse({
          package: packageName,
          version_group: group,
          version: version.version,
          is_lts: version.is_lts,
          artifact: {
            os: artifact.os,
            arch: artifact.arch,
            filename: artifact.filename,
            file_size: artifact.file_size,
            checksum: artifact.checksum,
            checksum_type: artifact.checksum_type,
            download_url: `/download/${packageName}/${version.version}/${artifact.os}/${artifact.arch}`,
          },
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function parseOptionalBoolean(value: unknown): boolean | undefined {
  const str = optionalString(value);
  if (!str) return undefined;
  if (str === "true" || str === "1") return true;
  if (str === "false" || str === "0") return false;
  return undefined;
}

function optionalString(value: unknown): string | undefined {
  if (typeof value === "string" && value.length > 0) return value;
  return undefined;
}

function selectArtifact(
  artifacts: ArtifactRow[],
  os?: string,
  arch?: string,
): ArtifactRow | undefined {
  const available = artifacts.filter((artifact) => artifact.status === "available");

  if (os && arch) {
    return available.find((artifact) => artifact.os === os && artifact.arch === arch);
  }

  return available[0];
}
