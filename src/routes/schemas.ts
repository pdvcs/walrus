import { extendZodWithOpenApi } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";

extendZodWithOpenApi(z);

// ── Shared ────────────────────────────────────────────────────────────────────

export const ErrorSchema = z.object({ error: z.string() }).openapi("Error");
export const LandingPageResponseSchema = z.string().openapi("LandingPageResponse");

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
    status: z
      .enum(["pending", "downloading", "available", "failed", "removed", "cooling_off"])
      .openapi({
        description:
          "Artifact lifecycle state, except that an artifact still inside its release embargo reports `cooling_off` rather than the `pending` it is stored as — the two are indistinguishable otherwise, and mean very different things to a caller.",
      }),
    available_at: z.string().datetime().nullable().optional().openapi({
      description: "When a `cooling_off` artifact becomes servable. Null for every other status.",
    }),
  })
  .openapi("Platform");

export const VersionSchema = z
  .object({
    version: z.string(),
    version_group: z.string(),
    is_lts: z.boolean(),
    status: z.enum(["available", "blocked", "cooling_off"]).openapi({
      description:
        "Whether the version can be fetched. `blocked` is a concrete match to a known critical CVE (any CVSS base score — v3, v4, or v2 — >= 9.0, or score-less CRITICAL) and takes precedence. `cooling_off` means no platform is servable yet because every candidate artifact is inside its release embargo. `available` means at least one platform is downloadable now, or is pending for ordinary sync reasons.",
    }),
    available_at: z.string().datetime().nullable().optional().openapi({
      description:
        "For `cooling_off`, when the first platform leaves its embargo. Null for every other status.",
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
    requires_range: z.boolean().openapi({
      description:
        "Whether this artifact can only be fetched with a `Range` request. An unranged GET of one is refused with 400 `range_required` rather than served, because a single request cannot complete inside the 3600s server deadline at this size. A ranged GET whose `If-Range` no longer matches is refused too, with 400 `stale_range_validator`, since the whole representation the RFC would have us send is the thing being refused. Published here so a client decides before it starts downloading.",
      example: false,
    }),
    upstream_url: z.string().nullable().optional().openapi({
      description:
        "URL the source bytes were fetched from. For an untransformed artifact this is also where the served bytes came from; for a transformed one it is the start of the provenance chain.",
    }),
    source_checksum: z.string().nullable().optional().openapi({
      description:
        "Digest of the bytes upstream published, verified before any transform ran. Null means the served bytes are upstream's own and `checksum` already covers them.",
    }),
    source_file_size: z.number().int().nullable().optional().openapi({
      description: "Byte count of the upstream source. Null on untransformed artifacts.",
    }),
    transform: z.string().nullable().optional().openapi({
      description:
        "Versioned identity of the conversion that produced the served bytes (e.g. `tar-bz2-to-zip@1`). Null means the artifact is untransformed.",
      example: "tar-bz2-to-zip@1",
    }),
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
    cvss_last_sync: z.string().nullable(),
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
    cvss: VulnSourceStatusSchema,
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
    // Which CVSS version produced `severity`. v2 has no CRITICAL band (v2 HIGH
    // spans 7.0-10.0), so a v2-sourced severity is not comparable to a v3/v4 one.
    severity_source: z.string().nullable(),
    cvss_v3_score: z.number().nullable(),
    cvss_v4_score: z.number().nullable(),
    cvss_v2_score: z.number().nullable(),
    summary: z.string().nullable(),
    affected: z.object({
      range: z.string(),
      matched_because: z.string().nullable(),
    }),
    fixed_in: z.string().nullable(),
    is_kev: z.boolean(),
    sources: z.array(z.string()),
    references: z.array(z.string()),
    suppression: z
      .object({
        reason: z.string(),
        expires_at: z.string().datetime().nullable(),
      })
      .nullable()
      .openapi({
        description:
          "Active operator assertion excluding this CVE from the download gate. The advisory remains visible.",
      }),
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
    severity_source: z.string().nullable(),
    cvss_v3_score: z.number().nullable(),
    cvss_v3_vector: z.string().nullable(),
    cvss_v4_score: z.number().nullable(),
    cvss_v4_vector: z.string().nullable(),
    cvss_v2_score: z.number().nullable(),
    cvss_v2_vector: z.string().nullable(),
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
    suppression: z
      .object({
        reason: z.string(),
        expires_at: z.string().datetime().nullable(),
      })
      .nullable(),
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

// ── GET /health, /app/health, /app/status ────────────────────────────────────

export const DegradationSchema = z
  .object({
    component: z.string().openapi({ example: "vuln-sync-nvd" }),
    reason: z.string(),
  })
  .openapi("Degradation");

export const HealthResponseSchema = z
  .object({
    isAvailable: z.boolean().openapi({
      example: true,
      description:
        "Whether the application is wholly available. Dependency degradations do not change " +
        "this value, and it remains true during the startup grace period.",
    }),
    gitUrl: z.string().url(),
    ts: z.string().datetime().openapi({ description: "Time this response was generated." }),
    started: z.string().datetime().openapi({ description: "Application startup time." }),
    inGracePeriod: z.boolean().openapi({
      description: "Whether the 300-second startup availability grace period is active.",
    }),
    version: z.string().openapi({ example: "0.2.0" }),
  })
  .openapi("HealthResponse");

export const StatusResponseSchema = HealthResponseSchema.extend({
  vuln_data_freshness: DataFreshnessSchema.nullable(),
  vuln_sync_status: VulnSyncStatusSchema.nullable(),
  degradations: z.array(DegradationSchema).openapi({
    description:
      "Parts of the system currently not doing their job unattended — stale or failing " +
      "vulnerability ingestion, stuck or disabled autonomous backfills. Empty means " +
      "self-healing is healthy. Shown as a banner on the admin UI.",
  }),
}).openapi("StatusResponse");

// ── GET /api/v1/packages/:name/availability ──────────────────────────────────

export const AvailabilityTransitionSchema = z
  .object({
    version: z.string(),
    status: z.enum(["blocked", "available"]),
    cve_id: z.string().nullable().openapi({
      description: "The CVE that caused a `blocked` transition. Null on `available`.",
    }),
    cvss_v3_score: z
      .number()
      .nullable()
      .openapi({
        description:
          "CVSS v3 base score of the blocking CVE at transition time, when stored. " +
          "A block may be explained by v4 or v2 instead — see `severity_source`.",
      }),
    cvss_v4_score: z.number().nullable().openapi({
      description: "CVSS v4 base score of the blocking CVE at transition time, when stored.",
    }),
    cvss_v2_score: z.number().nullable().openapi({
      description: "CVSS v2 base score of the blocking CVE at transition time, when stored.",
    }),
    severity: z.string().nullable(),
    severity_source: z
      .string()
      .nullable()
      .openapi({
        description:
          "Which CVSS version produced `severity`: nvd-cvss-v3 | nvd-cvss-v4 | nvd-cvss-v2. " +
          "Null on `available`, on unscored rows, and on events recorded before this column existed.",
      }),
    source: z.string().openapi({
      description: "Ingestion that produced the change: nvd | kev | osv | cvss | backfill.",
      example: "cvss",
    }),
    trigger: z.string().openapi({
      description: "`internal` for a scheduled run, `admin` for an operator.",
      example: "internal",
    }),
    at: z.string().datetime(),
  })
  .openapi("AvailabilityTransition");

export const AvailabilityHistoryResponseSchema = z
  .object({
    package: z.string(),
    version: z.string().nullable(),
    transitions: z.array(AvailabilityTransitionSchema),
  })
  .openapi("AvailabilityHistoryResponse");

// ── GET /download/:package/:version/:os/:arch ─────────────────────────────────

export const CoolingOffErrorSchema = z
  .object({
    error: z.string(),
    available_at: z.string().datetime(),
  })
  .openapi("CoolingOffError");
