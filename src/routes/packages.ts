import { Router } from "express";
import { ArtifactRow, PackageRow, SyncJobRow, VersionRow } from "../types/db.js";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import {
  getVersionAvailabilityStatus,
  GroupVersionInput,
  summarizeGroupsWithVulnGate,
} from "../services/vuln-service.js";
import { requiresRangedTransfer, TransferLimits } from "../services/transfer-policy.js";
import {
  CoolingOffErrorSchema,
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
  listVersionGroupsWithLts: (
    packageName: string,
  ) => Promise<{ version_group: string; is_lts: boolean }[]>;
  getEarliestCoolingOffInGroup: (
    packageName: string,
    group: string,
    opts?: { os?: string; arch?: string },
  ) => Promise<Date | null>;
  listAvailableVersionsByGroup: (
    packageName: string,
    opts?: { os?: string; arch?: string },
  ) => Promise<GroupVersionInput[]>;
  listAffectsForPackage: (packageName: string) => Promise<AffectsWithCveRow[]>;
  listVersions: (packageName: string, opts: { lts?: boolean }) => Promise<VersionRow[]>;
  listAvailableVersionsInGroup: (
    packageName: string,
    group: string,
    opts?: { os?: string; arch?: string },
  ) => Promise<VersionRow[]>;
  listArtifactsForVersion: (versionId: number) => Promise<ArtifactRow[]>;
  getRecentSyncJob: (packageName: string, withinMinutes: number) => Promise<SyncJobRow | null>;
  triggerOnDemandSync: (packageName: string) => Promise<void>;
  /** Defaults to the configured limits; injected so tests can drive the threshold. */
  transferLimits?: TransferLimits;
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
      const [allGroups, versions, affects] = await Promise.all([
        deps.listVersionGroupsWithLts(packageName),
        deps.listAvailableVersionsByGroup(packageName, { os, arch }),
        deps.listAffectsForPackage(packageName),
      ]);

      // summarizeGroupsWithVulnGate only sees versions with a servable artifact, so a group whose
      // versions are all embargoed or CVE-blocked would otherwise disappear from the listing
      // rather than reporting the null it is entitled to. Order follows allGroups (max
      // version_sort desc), which is the order the summary already produced for served groups.
      const summarized = new Map(
        summarizeGroupsWithVulnGate(versions, affects).map((group) => [group.group, group]),
      );
      const listed = new Set(allGroups.map(({ version_group }) => version_group));
      const groups = [
        ...allGroups.map(
          ({ version_group, is_lts }) =>
            summarized.get(version_group) ?? {
              group: version_group,
              is_lts,
              latest_available: null,
            },
        ),
        ...[...summarized.values()].filter((group) => !listed.has(group.group)),
      ];
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
      const [versionGroups, versions, affects] = await Promise.all([
        deps.listVersionGroups(packageName),
        deps.listVersions(packageName, lts === undefined ? {} : { lts }),
        deps.listAffectsForPackage(packageName),
      ]);

      const versionsWithArtifacts = await Promise.all(
        versions.map(async (version) => {
          const artifacts = await deps.listArtifactsForVersion(version.id);
          const platforms = artifacts.map((artifact) => {
            const until = coolingOffUntil(artifact);
            return {
              os: artifact.os,
              arch: artifact.arch,
              status: until === null ? artifact.status : ("cooling_off" as const),
              available_at: until === null ? null : until.toISOString(),
            };
          });

          const cveStatus = getVersionAvailabilityStatus(version.version, affects);
          const embargoed = platforms.filter((platform) => platform.status === "cooling_off");
          // The CVE gate wins: a blocked version stays blocked whatever its embargo says. Only
          // when *every* platform is embargoed is the version itself withheld -- one servable
          // platform means the caller has something to fetch.
          const withheld =
            cveStatus !== "blocked" &&
            embargoed.length > 0 &&
            embargoed.length === platforms.length;

          return {
            version: version.version,
            version_group: version.version_group,
            is_lts: version.is_lts,
            status: withheld ? ("cooling_off" as const) : cveStatus,
            available_at: withheld ? earliest(embargoed) : null,
            platforms,
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
      const [candidates, affects] = await Promise.all([
        deps.listAvailableVersionsInGroup(packageName, group, { os, arch }),
        deps.listAffectsForPackage(packageName),
      ]);
      const version = candidates.find(
        (candidate) => getVersionAvailabilityStatus(candidate.version, affects) !== "blocked",
      );
      if (!version) {
        // An embargo is a temporary, dated withholding -- distinct from "not synced yet" (202,
        // retry shortly) and from "nothing safe exists" (404). Reporting it as either tells the
        // caller to do the wrong thing.
        const until = await deps.getEarliestCoolingOffInGroup(packageName, group, { os, arch });
        if (until !== null) {
          res
            .status(423)
            .set("Retry-After", String(retryAfterSeconds(until)))
            .json(
              CoolingOffErrorSchema.parse({
                error: `No servable version for group ${group}: awaiting release from cooling off`,
                available_at: until.toISOString(),
              }),
            );
          return;
        }
      }

      if (!version && candidates.length === 0) {
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

      if (!version) {
        res.status(404).json({ error: `No safe version found for group ${group}` });
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
            requires_range: requiresRangedTransfer(artifact.file_size, deps.transferLimits),
          },
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}

/** The artifact's embargo expiry if it is still in force, else null. */
function coolingOffUntil(artifact: ArtifactRow): Date | null {
  const until = artifact.cooling_off_until;
  if (!until || until <= new Date()) return null;
  return until;
}

/** Earliest `available_at` among embargoed platforms — the first moment anything can be fetched. */
function earliest(platforms: { available_at: string | null }[]): string | null {
  const times = platforms
    .map((platform) => platform.available_at)
    .filter((at): at is string => at !== null)
    .sort();
  return times[0] ?? null;
}

function retryAfterSeconds(until: Date): number {
  return Math.max(1, Math.ceil((until.getTime() - Date.now()) / 1000));
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
