import { OpenAPIRegistry, OpenApiGeneratorV31 } from "@asteasolutions/zod-to-openapi";
import { z } from "zod";
import { Router } from "express";
import {
  CoolingOffErrorSchema,
  ErrorSchema,
  HealthResponseSchema,
  LatestArtifactResponseSchema,
  ListGroupsResponseSchema,
  ListPackagesResponseSchema,
  ListVersionsResponseSchema,
  SyncingResponseSchema,
  VulnsResponseSchema,
  ProductSearchResponseSchema,
  CveDetailResponseSchema,
  PackageVulnsResponseSchema,
} from "./schemas.js";

const registry = new OpenAPIRegistry();

// ── Reusable param schemas ────────────────────────────────────────────────────

const packageNameParam = z.object({
  name: z.string().openapi({ description: "Package name (e.g. `openjdk`, `golang`, `uv`)" }),
});

const platformQueryParams = z.object({
  os: z
    .string()
    .optional()
    .openapi({ description: "Operating system (e.g. `linux`, `mac`, `windows`)" }),
  arch: z
    .string()
    .optional()
    .openapi({ description: "CPU architecture (e.g. `x86_64`, `aarch64`)" }),
});

// ── Paths ─────────────────────────────────────────────────────────────────────

registry.registerPath({
  method: "get",
  path: "/api/v1/packages/",
  summary: "List enabled packages",
  operationId: "listPackages",
  tags: ["Packages"],
  responses: {
    200: {
      description: "List of enabled packages",
      content: { "application/json": { schema: ListPackagesResponseSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api/v1/packages/{name}/groups",
  summary: "List version groups for a package",
  operationId: "listVersionGroups",
  tags: ["Packages"],
  request: { params: packageNameParam, query: platformQueryParams },
  responses: {
    200: {
      description:
        "Version groups, optionally filtered to those with available artifacts for the given platform",
      content: { "application/json": { schema: ListGroupsResponseSchema } },
    },
    404: {
      description: "Package not found",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api/v1/packages/{name}/versions",
  summary: "List versions for a package",
  operationId: "listVersions",
  tags: ["Packages"],
  request: {
    params: packageNameParam,
    query: z.object({
      lts: z.boolean().optional().openapi({ description: "If true, return only LTS versions" }),
    }),
  },
  responses: {
    200: {
      description: "Versions with platform availability",
      content: { "application/json": { schema: ListVersionsResponseSchema } },
    },
    404: {
      description: "Package not found",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api/v1/packages/{name}/versions/{group}/latest",
  summary: "Get latest artifact for a version group and platform",
  operationId: "getLatestArtifact",
  tags: ["Packages"],
  request: {
    params: z.object({
      name: z.string().openapi({ description: "Package name" }),
      group: z.string().openapi({ description: "Version group (e.g. `21` for Java 21.x)" }),
    }),
    query: platformQueryParams,
  },
  responses: {
    200: {
      description: "Latest available artifact",
      content: { "application/json": { schema: LatestArtifactResponseSchema } },
    },
    202: {
      description: "No data cached yet; sync triggered. Retry after the indicated interval.",
      headers: {
        "Retry-After": {
          description: "Seconds to wait before retrying",
          schema: { type: "integer", example: 30 },
        },
      },
      content: { "application/json": { schema: SyncingResponseSchema } },
    },
    404: {
      description: "Package, group, or artifact not found",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/download/{package}/{version}/{os}/{arch}",
  summary: "Download a binary",
  operationId: "downloadArtifact",
  tags: ["Download"],
  request: {
    params: z.object({
      package: z.string(),
      version: z.string(),
      os: z.string(),
      arch: z.string(),
    }),
  },
  responses: {
    200: {
      description: "Binary file stream",
      headers: {
        "Content-Disposition": {
          description: 'attachment; filename="<filename>"',
          schema: { type: "string" },
        },
        "Content-Length": { schema: { type: "integer" } },
        "X-Checksum-Sha256": {
          description: "SHA-256 checksum (if available)",
          schema: { type: "string" },
        },
        "X-Checksum-Sha1": {
          description: "SHA-1 checksum (if available)",
          schema: { type: "string" },
        },
      },
      content: { "application/octet-stream": { schema: { type: "string", format: "binary" } } },
    },
    404: {
      description: "Artifact not found or not available",
      content: { "application/json": { schema: ErrorSchema } },
    },
    423: {
      description: "Artifact is within the cooling-off period and not yet released",
      headers: {
        "Retry-After": {
          description: "Seconds until the artifact is released",
          schema: { type: "integer" },
        },
      },
      content: { "application/json": { schema: CoolingOffErrorSchema } },
    },
  },
});

// ── Vulnerability intelligence ─────────────────────────────────────────────────

registry.registerPath({
  method: "get",
  path: "/api/v1/vulns",
  summary: "Look up known CVEs for a product/version",
  operationId: "queryVulns",
  tags: ["Vulnerabilities"],
  request: {
    query: z.object({
      product: z.string().openapi({ description: "Product name or alias (e.g. `openjdk`, `npp`)" }),
      version: z.string().optional().openapi({ description: "Version to range-check against" }),
      include_unmatched: z
        .boolean()
        .optional()
        .openapi({ description: "Also return CVEs whose ranges did not match the version" }),
    }),
  },
  responses: {
    200: {
      description:
        "Resolution + matching CVEs. Unresolved products return 200 with candidates and empty vulns.",
      content: { "application/json": { schema: VulnsResponseSchema } },
    },
    400: {
      description: "Missing `product` parameter",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api/v1/vulns/products/search",
  summary: "Autocomplete product names/aliases",
  operationId: "searchProducts",
  tags: ["Vulnerabilities"],
  request: { query: z.object({ q: z.string().openapi({ description: "Search prefix/term" }) }) },
  responses: {
    200: {
      description: "Ranked product matches (top 10)",
      content: { "application/json": { schema: ProductSearchResponseSchema } },
    },
    400: {
      description: "Missing `q` parameter",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api/v1/cves/{cveId}",
  summary: "CVE detail",
  operationId: "getCve",
  tags: ["Vulnerabilities"],
  request: {
    params: z.object({ cveId: z.string().openapi({ description: "CVE id, e.g. CVE-2023-40031" }) }),
  },
  responses: {
    200: {
      description: "CVE metadata, KEV status, affected products, references",
      content: { "application/json": { schema: CveDetailResponseSchema } },
    },
    400: {
      description: "Malformed CVE id",
      content: { "application/json": { schema: ErrorSchema } },
    },
    404: {
      description: "Unknown CVE (or affects no tracked package)",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api/v1/packages/{name}/vulns",
  summary: "CVEs affecting a package's cached versions",
  operationId: "getPackageVulns",
  tags: ["Vulnerabilities"],
  request: {
    params: packageNameParam,
    query: z.object({
      version: z
        .string()
        .optional()
        .openapi({ description: "Restrict to a single cached version" }),
    }),
  },
  responses: {
    200: {
      description:
        "Per-cached-version CVE counts + matches. Untracked packages return tracked:false.",
      content: { "application/json": { schema: PackageVulnsResponseSchema } },
    },
    404: {
      description: "Unknown package",
      content: { "application/json": { schema: ErrorSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/health",
  summary: "Health check",
  operationId: "health",
  tags: ["Utility"],
  responses: {
    200: {
      description: "Service is healthy",
      content: { "application/json": { schema: HealthResponseSchema } },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/api",
  summary: "API documentation",
  operationId: "apiDocs",
  tags: ["Utility"],
  responses: {
    200: {
      description: "API documentation as Markdown or HTML depending on Accept header",
      content: {
        "text/markdown": { schema: { type: "string" } },
        "text/html": { schema: { type: "string" } },
      },
    },
  },
});

registry.registerPath({
  method: "get",
  path: "/openapi.json",
  summary: "OpenAPI specification",
  operationId: "openApiSpec",
  tags: ["Utility"],
  responses: {
    200: {
      description: "OpenAPI 3.1.0 specification for this API",
      content: { "application/json": { schema: { type: "object" } } },
    },
  },
});

// ── Generate & serve ──────────────────────────────────────────────────────────

const generator = new OpenApiGeneratorV31(registry.definitions);

export const openApiSpec = generator.generateDocument({
  openapi: "3.1.0",
  info: {
    title: "Walrus API",
    version: "1.0.0",
    description:
      "Walrus is a policy- and identity-aware ingress engine for software packages. " +
      "It discovers, caches, and serves package binaries based on policy expressed in configuration files.",
  },
});

export function createOpenApiRouter(): Router {
  const router = Router();
  router.get("/", (_req, res) => {
    res.json(openApiSpec);
  });
  return router;
}
