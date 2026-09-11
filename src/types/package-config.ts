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
    // Applied to the whole response body (not per-href): the first capture group yields a version
    // string. The matched link is never treated as the artifact URL — see the strategy's docs.
    pattern: z.string().refine(
      (p) => {
        try {
          return new RegExp(p).exec("") !== undefined && /\((?!\?)/.test(p);
        } catch {
          return false;
        }
      },
      { message: "pattern must be a valid regex containing a capture group" },
    ),
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
  z.object({
    type: z.literal("rust-channel"),
    // S3 ListObjectsV2 endpoint (XML) used to enumerate archived per-version manifests, e.g.
    // "https://static.rust-lang.org/?list-type=2&prefix=dist/channel-rust-". Rust ships no binary
    // assets on GitHub Releases and no JSON manifest, so its TOML channel manifests are the only
    // source; the bucket's list API enumerates them without scraping or GitHub rate limits.
    listing_url: z.string(),
    // One archived manifest per version; {version} is substituted. e.g.
    // "https://static.rust-lang.org/dist/channel-rust-{version}.toml".
    manifest_url_template: z.string(),
    // Only fetch manifests for the newest N versions after min_version is applied. Each manifest
    // is ~0.9 MB, so this bounds discovery work; retention prunes further downstream.
    max_versions: z.number().int().positive().optional(),
    // Which [pkg.<name>] table holds the toolchain artifacts. "rust" is the full rustup component
    // (rustc + cargo + rust-std + rust-docs).
    package: z.string().default("rust"),
  }),
  z.object({
    type: z.literal("dotnet-releases"),
    // The channel document(s), one per major.minor. e.g.
    // "https://raw.githubusercontent.com/dotnet/core/main/release-notes/10.0/releases.json".
    // Carries the whole channel unpaginated, with inline SHA-512 hashes and no sidecar files.
    // A list tracks several channels in one package (e.g. the hosting bundle across 8.0 and 10.0),
    // since .NET publishes a separate document per channel rather than one index.
    url: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
    // Which component of each release to serve. "sdk" walks `sdks[]` (one entry per active
    // feature band, each with its bundled runtime version); "runtime" and "aspnetcore-runtime"
    // read that single object from the release.
    component: z.enum(["sdk", "runtime", "aspnetcore-runtime"]),
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
  // Shape of the values `lts_api_path` points at. "groups" is every mode that predates this
  // field and stays the default: each value already IS a version group, as Adoptium's
  // `$.available_lts_releases` returns ([8, 11, 17, 21, 25] against openjdk's major-number
  // groups). "tags" says the values are release tags that must be reduced to groups the same
  // way a discovered release is — PowerShell's `$.LTSReleaseTag` returns ["v7.4.20", "v7.6.6"],
  // which names the current patch of each LTS line rather than the line itself.
  //
  // Named rather than inferred, for the reason `files_shape` is: deciding per value whether it
  // looks like a tag or a group would quietly mark the wrong versions LTS the first time an
  // upstream changed its tag style, and a silently wrong `is_lts` is worse than a loud failure.
  lts_api_shape: z.enum(["groups", "tags"]).default("groups"),
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
  // CVE version normalisation (WAL-78, ADR-008). A regex whose FIRST CAPTURE GROUP yields the
  // version used for CVE range evaluation. Set it only where the served version embeds an
  // upstream version rather than being one: gitwindows serves 2.55.0.5 (Git 2.55.0, Windows
  // rebuild 5) against CVE ranges that name three-component Git, so `^(\d+\.\d+\.\d+)`
  // makes the gate compare 2.55.0. Absent = compare the served version directly.
  //
  // Deliberately explicit rather than inferred: silently truncating any four-component version
  // would change matching for every package that later grows one.
  cve_version_extract: z
    .string()
    .min(1)
    .refine(
      (p) => {
        try {
          return new RegExp(p).exec("") !== undefined && /\((?!\?)/.test(p);
        } catch {
          return false;
        }
      },
      { message: "cve_version_extract must be a valid regex containing a capture group" },
    )
    .optional(),
});

export type VulnerabilitiesConfig = z.infer<typeof VulnerabilitiesSchema>;

export const PackageConfigSchema = z
  .object({
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
  })
  .superRefine((config, ctx) => {
    // `directory-listing` is version-list-only: the listing host supplies version strings and the
    // download host is a different service, so there is no href-as-artifact-URL fallback. A
    // platform without `url_template` therefore cannot produce an artifact, and a config that
    // omits one should fail validation rather than silently discover nothing.
    if (config.discovery.type !== "directory-listing") return;
    config.platforms.forEach((platform, index) => {
      if (!platform.url_template) {
        ctx.addIssue({
          code: "custom",
          path: ["platforms", index, "url_template"],
          message:
            "directory-listing requires url_template on every [[platforms]] block: the listing supplies versions only, and the download host is separate",
        });
      }
    });
  });

export type PackageConfig = z.infer<typeof PackageConfigSchema>;
export type Platform = z.infer<typeof PlatformSchema>;
export type TransformConfig = z.infer<typeof TransformSchema>;
export type DiscoveryConfig = z.infer<typeof DiscoverySchema>;
export type VersioningConfig = z.infer<typeof VersioningSchema>;
export type ChecksumConfig = z.infer<typeof ChecksumSchema>;
