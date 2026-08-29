import { z } from "zod";

// Repackaging stage (WAL-56/57): declared per platform; `extension` / `filename_template` here
// describe what walrus *serves*, while the platform's own `extension` / `filename_template` keep
// meaning what upstream publishes and what asset matching looks for. One member today; a second
// conversion is a new file in src/transform/ plus a variant here, never a DownloadService change.
const TransformSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("tar-bz2-to-zip"),
    extension: z.string(),
    filename_template: z.string().optional(),
    // Post-transform gate, enforced before the artifact reaches `available`: each path must have
    // been a file entry in the transformed output, and the output must hold at least
    // `min_entries` file entries. A transform that silently produced an empty or truncated
    // archive would otherwise be served.
    require_paths: z.array(z.string().min(1)).default([]),
    min_entries: z.number().int().positive().optional(),
    // Hardlink targets must still be in the link cache when their hardlink streams past; this
    // is the cache's byte budget (default 64 MiB). Size it to the measured distance between a
    // target and its farthest hardlink in the real archive, not to a guess.
    link_cache_bytes: z.number().int().positive().optional(),
    // Symlinks are a hard failure (WAL-57 AC4: a zip that extracts and then misbehaves is the
    // worst outcome) EXCEPT paths listed here, which are dropped and reported. Exists for
    // entries the target estate provably cannot miss — record the evidence in a comment.
    drop_symlinks: z.array(z.string().min(1)).default([]),
  }),
]);

const PlatformSchema = z.object({
  os: z.enum(["windows", "macos", "linux"]),
  arch: z.enum(["x86-64", "arm64"]),
  os_upstream: z.string(),
  arch_upstream: z.string(),
  extension: z.string(),
  filename_template: z.string().optional(),
  url_template: z.string().optional(),
  name_must_contain: z.string().optional(),
  transform: TransformSchema.optional(),
});

const DiscoverySchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("github-releases"),
    repo: z.string(),
    include_prereleases: z.boolean().default(false),
    tag_pattern: z.string().optional(),
    // When set, version is extracted from each asset filename rather than the release tag.
    // One DiscoveredVersion is produced per unique extracted version. Enables {tag} in filename_template.
    asset_version_pattern: z.string().optional(),
    // Limit the number of releases fetched from GitHub. Useful for repos with many assets per release
    // where the default of 100 releases causes GitHub API timeouts.
    max_releases: z.number().int().positive().optional(),
  }),
  z
    .object({
      type: z.literal("json-api"),
      url: z.string().optional(),
      // Two-step submode
      explicit_versions: z.array(z.number()).optional(), // alternative to url+versions_path
      versions_path: z.string().optional(),
      release_url_template: z.string().optional(),
      release_download_url_field: z.string().optional(), // field name for download URL in release records
      release_filename_field: z.string().optional(), // field name for filename in release records
      release_date_field: z.string().optional(), // field name for release publish date (ISO 8601) in release records
      // Inline submode
      releases_path: z.string().optional(),
      release_version_field: z.string().optional(),
      tag_pattern: z.string().optional(),
      files_field: z.string().optional(),
      // Shape of whatever `files_field` points at. "array" is every mode that predates this
      // field and stays the default; "platform-map" says the value is an object whose *keys*
      // are the platform discriminator, each `[[platforms]]` entry selecting its download by
      // `os_upstream`. Named rather than inferred: overloading `file_os_field` to mean "or the
      // key, if the value happens to be an object" is what makes sub-modes hard to tell apart.
      files_shape: z.enum(["array", "platform-map"]).optional(),
      file_os_field: z.string().optional(),
      file_arch_field: z.string().optional(),
      file_kind_field: z.string().optional(),
      file_kind_value: z.string().optional(),
      file_filename_field: z.string().optional(),
      file_url_base: z.string().optional(),
      file_checksum_field: z.string().optional(),
      // platform-map only: fields read from each download object.
      file_url_field: z.string().optional(), // download URL; the filename comes from its tail
      file_checksum_url_field: z.string().optional(), // URL of a checksum sidecar
      file_size_field: z.string().optional(), // byte count, checked against the transfer
      release_lts_field: z.string().optional(), // field whose truthy string value indicates LTS
    })
    .superRefine((discovery, ctx) => {
      const platformMap = discovery.files_shape === "platform-map";

      if (platformMap && !discovery.files_field) {
        ctx.addIssue({
          code: "custom",
          path: ["files_field"],
          message: 'files_shape = "platform-map" requires files_field',
        });
      }
      if (platformMap && !discovery.file_url_field) {
        ctx.addIssue({
          code: "custom",
          path: ["file_url_field"],
          message:
            'files_shape = "platform-map" requires file_url_field — the download object carries the URL, and the filename is its tail',
        });
      }

      // Fields that belong to the array shape and have no meaning against a keyed map. Left
      // in a config they would be silently ignored, which is the failure this schema exists to
      // turn into an error.
      const arrayOnly = [
        "file_os_field",
        "file_arch_field",
        "file_kind_field",
        "file_kind_value",
        "file_filename_field",
        "file_url_base",
      ] as const;
      for (const field of arrayOnly) {
        if (platformMap && discovery[field] !== undefined) {
          ctx.addIssue({
            code: "custom",
            path: [field],
            message: `${field} has no meaning when files_shape = "platform-map"; the key selects the download`,
          });
        }
      }

      const mapOnly = ["file_url_field", "file_checksum_url_field", "file_size_field"] as const;
      for (const field of mapOnly) {
        if (!platformMap && discovery[field] !== undefined) {
          ctx.addIssue({
            code: "custom",
            path: [field],
            message: `${field} requires files_shape = "platform-map"`,
          });
        }
      }
    }),
  z.object({
    type: z.literal("directory-listing"),
    url: z.string(),
    pattern: z.string(),
  }),
  z.object({
    type: z.literal("xml-api"),
    url: z.string(),
    versions_path: z.string(), // JSONPath into parsed XML → string[]
    version_filter: z.string().optional(), // regex to keep only matching versions
    tag_pattern: z.string().optional(),
    release_date_url_template: z.string().optional(), // per-version URL, {version} substituted
    release_date_path: z.string().optional(), // JSONPath into that response → timestamp (ms or ISO)
  }),
]);

const VersioningSchema = z.object({
  type: z.enum(["semver", "major-minor", "calver"]),
  version_group_extract: z.string(),
  min_version: z.string().optional(),
  lts_support: z.boolean().default(false),
  lts_source: z.enum(["none", "api", "even_major", "explicit"]).default("none"),
  lts_api_url: z.string().optional(),
  lts_api_path: z.string().optional(),
  lts_min_group: z.number().optional(),
  lts_groups: z.array(z.string()).optional(),
});

const RetentionSchema = z.object({
  versions_per_group: z.number().int().positive().default(3),
  groups_to_keep: z.number().int().positive().optional(),
  cooling_off_days: z.number().int().nonnegative().optional(),
});

const ChecksumSchema = z.object({
  type: z.enum(["inline-api", "separate-file", "github-asset", "github-asset-digest", "none"]),
  algorithm: z.enum(["sha256", "sha1", "sha512"]).default("sha256"),
  // separate-file
  url_template: z.string().optional(),
  parse_pattern: z.string().optional(),
  // github-asset
  asset_suffix: z.string().optional(),
  // inline-api
  response_path: z.string().optional(),
});

const VulnerabilitiesSchema = z.object({
  // NVD CPE 2.3 `vendor:product` pairs; first entry is primary. Verify against
  // the NVD CPE dictionary when authoring (plan §2 / WAL-3 MANUAL_TEST).
  cpes: z
    .array(
      z
        .string()
        .refine((s) => s.split(":").length === 2 && s.split(":").every((p) => p.length > 0), {
          message: "cpe must be a single 'vendor:product' pair (exactly one colon, both non-empty)",
        }),
    )
    .default([]),
  // Optional OSV cross-check mapping.
  osv: z.object({ ecosystem: z.string().min(1), name: z.string().min(1) }).optional(),
  // Human-name aliases for resolution / autocomplete (normalized on load).
  aliases: z.array(z.string().min(1)).default([]),
});

export type VulnerabilitiesConfig = z.infer<typeof VulnerabilitiesSchema>;

export const PackageConfigSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/, "Name must be lowercase alphanumeric with hyphens"),
  display_name: z.string(),
  vendor: z.string(),
  website: z.string().optional(),
  description: z.string().optional(),
  discovery: DiscoverySchema,
  versioning: VersioningSchema,
  retention: RetentionSchema.default({ versions_per_group: 3 }),
  checksum: ChecksumSchema.optional(),
  platforms: z.array(PlatformSchema).min(1),
  vulnerabilities: VulnerabilitiesSchema.optional(),
});

export type PackageConfig = z.infer<typeof PackageConfigSchema>;
export type Platform = z.infer<typeof PlatformSchema>;
export type TransformConfig = z.infer<typeof TransformSchema>;
export type DiscoveryConfig = z.infer<typeof DiscoverySchema>;
export type VersioningConfig = z.infer<typeof VersioningSchema>;
export type ChecksumConfig = z.infer<typeof ChecksumSchema>;
