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
    latest_available: z
      .string()
      .nullable()
      .openapi({ description: "Latest available version string, or null if none cached" }),
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

// ── GET /health ───────────────────────────────────────────────────────────────

export const HealthResponseSchema = z
  .object({
    status: z.string().openapi({ example: "ok" }),
    service: z.string().openapi({ example: "walrus" }),
  })
  .openapi("HealthResponse");

// ── GET /download/:package/:version/:os/:arch ─────────────────────────────────

export const CoolingOffErrorSchema = z
  .object({
    error: z.string(),
    available_at: z.string().datetime(),
  })
  .openapi("CoolingOffError");
