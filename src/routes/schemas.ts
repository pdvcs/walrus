import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

extendZodWithOpenApi(z);

// ── Shared ────────────────────────────────────────────────────────────────────

export const ErrorSchema = z.object({ error: z.string() }).openapi("Error");

// ── GET /api/v1/packages/ ─────────────────────────────────────────────────────

export const PackageSchema = z
  .object({
    name: z.string(),
    display_name: z.string(),
    vendor: z.string(),
    description: z.string().nullable().optional(),
    website: z.string().nullable().optional(),
  })
  .openapi("Package");

export const ListPackagesResponseSchema = z
  .object({ packages: z.array(PackageSchema) })
  .openapi("ListPackagesResponse");

// ── GET /api/v1/packages/:name/groups ────────────────────────────────────────

export const VersionGroupSummarySchema = z
  .object({
    group: z.string().openapi({ description: "Version group label (e.g. `21`)" }),
    is_lts: z.boolean(),
    latest_available: z.string().nullable().openapi({
      description:
        "Latest cached version free of known critical (CVSS >= 9.0) CVEs. Null means no version in the group is free of them — nothing safe to recommend, not nothing cached. Per-version CVE detail: /packages/{name}/vulns.",
    }),
  })
  .openapi("VersionGroupSummary");

export const ListGroupsResponseSchema = z
  .object({
    package: z.string(),
    groups: z.array(VersionGroupSummarySchema),
  })
  .openapi("ListGroupsResponse");

// ── GET /api/v1/packages/:name/versions ──────────────────────────────────────

export const PlatformSchema = z
  .object({
    os: z.string(),
    arch: z.string(),
    status: z.enum(["pending", "downloading", "available", "failed", "removed"]),
  })
  .openapi("Platform");

export const VersionSchema = z
  .object({
    version: z.string(),
    version_group: z.string(),
    is_lts: z.boolean(),
    status: z.enum(["available", "blocked"]).openapi({
      description:
        "Version eligibility under the critical-CVE gate. Blocked means a concrete match to a known critical CVE (CVSS >= 9.0, or score-less CRITICAL).",
    }),
    platforms: z.array(PlatformSchema),
  })
  .openapi("Version");

export const ListVersionsResponseSchema = z
  .object({
    package: z.string(),
    version_groups: z.array(z.string()),
    versions: z.array(VersionSchema),
  })
  .openapi("ListVersionsResponse");

// ── GET /api/v1/packages/:name/versions/:group/latest ────────────────────────

export const ArtifactSchema = z
  .object({
    os: z.string(),
    arch: z.string(),
    filename: z.string(),
    file_size: z.number().int().nullable().optional(),
    checksum: z.string().nullable().optional(),
    checksum_type: z.string().nullable().optional().openapi({ example: "sha256" }),
    download_url: z.string(),
  })
  .openapi("Artifact");

export const LatestArtifactResponseSchema = z
  .object({
    package: z.string(),
    version_group: z.string(),
    version: z.string(),
    is_lts: z.boolean(),
    artifact: ArtifactSchema,
  })
  .openapi("LatestArtifactResponse");

export const SyncingResponseSchema = z
  .object({
    status: z.string().openapi({ example: "syncing" }),
    message: z.string(),
  })
  .openapi("SyncingResponse");

// ── Vulnerability intelligence (plan §4) ──────────────────────────────────────

export const VULN_DISCLAIMER =
  "Absence of results does not imply the product/version is safe. Data comes from " +
  "public sources (NVD, CISA KEV, OSV) which may lag or be incomplete.";

export const DataFreshnessSchema = z
  .object({
    nvd_last_sync: z.string().nullable(),
    kev_last_sync: z.string().nullable(),
    osv_last_sync: z.string().nullable(),
  })
  .openapi("DataFreshness");

export const VulnSourceStatusSchema = z
  .object({
    last_attempt: z.string().nullable(),
    last_success: z.string().nullable(),
    last_failure: z.string().nullable(),
    last_ok: z.boolean().nullable(),
  })
  .openapi("VulnSourceStatus");

export const VulnSyncStatusSchema = z
  .object({
    nvd: VulnSourceStatusSchema,
    kev: VulnSourceStatusSchema,
    osv: VulnSourceStatusSchema,
  })
  .openapi("VulnSyncStatus");

export const MatchCandidateSchema = z
  .object({
    slug: z.string().openapi({ description: "Walrus package name" }),
    display_name: z.string(),
    score: z.number(),
  })
  .openapi("MatchCandidate");

export const MatchSchema = z
  .object({
    resolved: z.boolean(),
    product_slug: z.string().nullable().openapi({ description: "Resolved walrus package name" }),
    display_name: z.string().nullable(),
    confidence: z.number().nullable(),
    method: z.enum(["slug-exact", "alias-exact", "fuzzy"]).nullable(),
    candidates: z.array(MatchCandidateSchema),
  })
  .openapi("VulnMatch");

export const VulnCountsSchema = z
  .object({
    total: z.number().int(),
    critical: z.number().int(),
    high: z.number().int(),
    medium: z.number().int(),
    low: z.number().int(),
    kev: z.number().int(),
  })
  .openapi("VulnCounts");

export const VulnItemSchema = z
  .object({
    cve_id: z.string(),
    severity: z.string().nullable(),
    cvss_v3_score: z.number().nullable(),
    summary: z.string().nullable(),
    affected: z.object({
      range: z.string(),
      matched_because: z.string().nullable(),
    }),
    fixed_in: z.string().nullable(),
    is_kev: z.boolean(),
    sources: z.array(z.string()),
    references: z.array(z.string()),
  })
  .openapi("VulnItem");

export const VulnsResponseSchema = z
  .object({
    query: z.object({ product: z.string(), version: z.string().nullable() }),
    match: MatchSchema,
    vulns: z.array(VulnItemSchema),
    unmatched_vulns: z.array(VulnItemSchema).optional(),
    counts: VulnCountsSchema,
    version_parse_warning: z.string().optional(),
    data_freshness: DataFreshnessSchema,
    disclaimer: z.string(),
  })
  .openapi("VulnsResponse");

// GET /api/v1/vulns/products/search
export const ProductSearchResultSchema = z
  .object({ slug: z.string(), display_name: z.string(), score: z.number() })
  .openapi("ProductSearchResult");

export const ProductSearchResponseSchema = z
  .object({
    query: z.string(),
    results: z.array(ProductSearchResultSchema),
  })
  .openapi("ProductSearchResponse");

export const VulnProductResponseSchema = z
  .object({
    name: z.string(),
    display_name: z.string(),
    vendor: z.string(),
    description: z.string().nullable(),
    website: z.string().nullable(),
    tracked: z.boolean(),
    aliases: z.array(z.object({ alias: z.string(), source: z.string() })),
    cpes: z.array(
      z.object({
        cpe_vendor: z.string(),
        cpe_product: z.string(),
        is_primary: z.boolean(),
      }),
    ),
    osv: z.object({ ecosystem: z.string(), name: z.string() }).nullable(),
    cve_count: z.number().int().nonnegative(),
  })
  .openapi("VulnProductResponse");

// GET /api/v1/cves/:cveId
export const CveAffectedProductSchema = z
  .object({
    slug: z.string(),
    display_name: z.string(),
    range: z.string(),
    fixed_in: z.string().nullable(),
    source: z.string(),
  })
  .openapi("CveAffectedProduct");

export const CveDetailResponseSchema = z
  .object({
    cve_id: z.string(),
    published_at: z.string().nullable(),
    modified_at: z.string().nullable(),
    severity: z.string().nullable(),
    cvss_v3_score: z.number().nullable(),
    cvss_v3_vector: z.string().nullable(),
    description: z.string().nullable(),
    is_kev: z.boolean(),
    kev_added_at: z.string().nullable(),
    affected_products: z.array(CveAffectedProductSchema),
    references: z.array(z.string()),
    data_freshness: DataFreshnessSchema,
    disclaimer: z.string(),
  })
  .openapi("CveDetailResponse");

// GET /api/v1/packages/:name/vulns
export const PackageVersionVulnSchema = z
  .object({
    cve_id: z.string(),
    severity: z.string().nullable(),
    fixed_in: z.string().nullable(),
    is_kev: z.boolean(),
    matched_because: z.string().nullable(),
  })
  .openapi("PackageVersionVuln");

export const PackageVersionVulnsSchema = z
  .object({
    version: z.string(),
    version_group: z.string(),
    counts: VulnCountsSchema,
    vulns: z.array(PackageVersionVulnSchema),
  })
  .openapi("PackageVersionVulns");

export const PackageVulnsResponseSchema = z
  .object({
    package: z.string(),
    tracked: z.boolean(),
    versions: z.array(PackageVersionVulnsSchema),
    data_freshness: DataFreshnessSchema,
    disclaimer: z.string(),
  })
  .openapi("PackageVulnsResponse");

// ── GET /health ───────────────────────────────────────────────────────────────

export const HealthResponseSchema = z
  .object({
    status: z.string().openapi({ example: "ok" }),
    service: z.string().openapi({ example: "walrus" }),
    vuln_data_freshness: DataFreshnessSchema.nullable(),
    vuln_sync_status: VulnSyncStatusSchema.nullable(),
  })
  .openapi("HealthResponse");

// ── GET /download/:package/:version/:os/:arch ─────────────────────────────────

export const CoolingOffErrorSchema = z
  .object({
    error: z.string(),
    available_at: z.string().datetime(),
  })
  .openapi("CoolingOffError");
