import { Router } from "express";
import { CveDetailResponseSchema, VULN_DISCLAIMER } from "./schemas.js";
import { CveRow, AffectedPackageRow } from "../db/queries/cves.js";
import { describeRange } from "../vuln/version-ranges.js";
import { DataFreshness } from "./vulns.js";

const CVE_ID_RE = /^CVE-\d{4}-\d{4,}$/i;

export interface CvesRouteDeps {
  getCve: (cveId: string) => Promise<CveRow | null>;
  listAffectedPackages: (cveId: string) => Promise<AffectedPackageRow[]>;
  getDataFreshness: () => Promise<DataFreshness>;
}

/**
 * GET /api/v1/cves/:cveId — CVE detail: metadata, KEV status, affected packages
 * with described ranges + provenance, references. 400 on malformed id, 404 when
 * unknown. See plan §4, WAL-12.
 */
export function createCvesRouter(deps: CvesRouteDeps): Router {
  const router = Router();

  router.get("/:cveId", async (req, res, next) => {
    try {
      const cveId = req.params.cveId.toUpperCase();
      if (!CVE_ID_RE.test(cveId)) {
        res.status(400).json({ error: "malformed CVE id — expected CVE-YYYY-NNNN…" });
        return;
      }

      const cve = await deps.getCve(cveId);
      if (!cve) {
        res.status(404).json({ error: "CVE not found (may not affect any tracked package)" });
        return;
      }

      const affected = await deps.listAffectedPackages(cveId);
      const freshness = await deps.getDataFreshness();
      const raw = cve.raw as { cve?: { references?: Array<{ url: string }> } } | null;

      res.json(
        CveDetailResponseSchema.parse({
          cve_id: cve.id,
          published_at: cve.published_at ? cve.published_at.toISOString() : null,
          modified_at: cve.modified_at ? cve.modified_at.toISOString() : null,
          severity: cve.severity,
          cvss_v3_score: cve.cvss_v3_score !== null ? Number(cve.cvss_v3_score) : null,
          cvss_v3_vector: cve.cvss_v3_vector,
          description: cve.description,
          is_kev: cve.is_kev,
          kev_added_at: cve.kev_added_at ? cve.kev_added_at.toISOString().slice(0, 10) : null,
          affected_products: affected.map((r) => ({
            slug: r.package_name,
            display_name: r.display_name,
            range: describeRange({
              versionStart: r.version_start,
              versionStartExcl: r.version_start_excl,
              versionEnd: r.version_end,
              versionEndExcl: r.version_end_excl,
              exactVersion: r.exact_version,
            }),
            fixed_in: r.fixed_in,
            source: r.source,
          })),
          references: (raw?.cve?.references ?? []).map((r) => r.url),
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
