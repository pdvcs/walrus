import { Router } from "express";
import { PackageVulnsResponseSchema, VULN_DISCLAIMER } from "./schemas.js";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { crossReferenceVersions, CachedVersionInput } from "../services/vuln-service.js";
import { DataFreshness } from "./vulns.js";

export interface PackageVulnsRouteDeps {
  packageExists: (name: string) => Promise<boolean>;
  isTracked: (name: string) => Promise<boolean>;
  listCachedVersions: (name: string, version?: string) => Promise<CachedVersionInput[]>;
  listAffectsForPackage: (name: string) => Promise<AffectsWithCveRow[]>;
  getDataFreshness: () => Promise<DataFreshness>;
}

/**
 * GET /api/v1/packages/:name/vulns — the walrus-native headline feature:
 * cross-reference cve_affects against the package's cached versions. Untracked
 * packages return tracked:false (200); unknown packages 404. See plan §4, WAL-13.
 */
export function createPackageVulnsRouter(deps: PackageVulnsRouteDeps): Router {
  const router = Router();

  router.get("/:name/vulns", async (req, res, next) => {
    try {
      const name = req.params.name;
      const version = typeof req.query.version === "string" ? req.query.version : undefined;

      if (!(await deps.packageExists(name))) {
        res.status(404).json({ error: `Unknown package: ${name}` });
        return;
      }

      const freshness = await deps.getDataFreshness();

      if (!(await deps.isTracked(name))) {
        res.json(
          PackageVulnsResponseSchema.parse({
            package: name,
            tracked: false,
            versions: [],
            data_freshness: freshness,
            disclaimer: VULN_DISCLAIMER,
          }),
        );
        return;
      }

      const [cached, affects] = await Promise.all([
        deps.listCachedVersions(name, version),
        deps.listAffectsForPackage(name),
      ]);

      res.json(
        PackageVulnsResponseSchema.parse({
          package: name,
          tracked: true,
          versions: crossReferenceVersions(cached, affects),
          data_freshness: freshness,
          disclaimer: VULN_DISCLAIMER,
        }),
      );
    } catch (err) {
      next(err);
    }
  });

  return router;
}
