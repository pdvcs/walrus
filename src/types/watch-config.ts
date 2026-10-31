import { z } from "zod";
import { VulnerabilitiesSchema } from "./package-config.js";

/** A regex with exactly one capture group, as `tag_pattern` is everywhere else in walrus. */
const CapturePattern = z.string().refine(
  (p) => {
    try {
      return new RegExp(`${p}|`).exec("")!.length === 2;
    } catch {
      return false;
    }
  },
  { message: "tag_pattern must be a valid regex with exactly one capture group" },
);

/**
 * How to find the package's current release (WAL-54). Walrus discovers no versions for a watch
 * entry, so without this it cannot answer "is the current release affected?". Deliberately
 * smaller than a discovery strategy: it resolves ONE version string and stores nothing else.
 *   json            GET a JSON document and read one value, e.g. PyPI `$.info.version`
 *   github-release  the repo's latest non-prerelease release tag
 */
export const LatestVersionSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("json"),
    url: z.string().url(),
    version_path: z.string().min(1),
    tag_pattern: CapturePattern.optional(),
  }),
  z.strictObject({
    type: z.literal("github-release"),
    repo: z.string().regex(/^[\w.-]+\/[\w.-]+$/, "repo must be owner/name"),
    tag_pattern: CapturePattern.optional(),
  }),
]);

export type LatestVersionConfig = z.infer<typeof LatestVersionSchema>;

/**
 * Watch-only package definition (`watchlist/*.toml`).
 *
 * A watched package is tracked for vulnerabilities but never discovered,
 * downloaded, or served — walrus holds no binaries for it. The vuln pipeline is
 * keyed purely on `packages.name` via `package_cpes` / `package_aliases` /
 * `packages.osv_*` and never touches `versions` or `artifacts`, so identity plus
 * a `[vulnerabilities]` section is all it needs.
 *
 * Deliberately a separate schema from `PackageConfigSchema` rather than making
 * discovery/versioning/platforms conditionally optional there: `packages/` keeps
 * meaning "things walrus serves", and a served package that loses its platforms
 * block still fails validation.
 *
 * Strict (WAL-35): a served `packages/*.toml` copied into `watchlist/` fails to load and
 * names the offending key, instead of silently shedding its discovery/platforms sections
 * and becoming a watch-only package.
 */
export const WatchConfigSchema = z.strictObject({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/, "Name must be lowercase alphanumeric with hyphens"),
  display_name: z.string(),
  vendor: z.string(),
  website: z.string().optional(),
  description: z.string().optional(),
  // Required here (unlike on PackageConfig): a watch entry with no vuln config
  // would create a package row that does nothing at all.
  vulnerabilities: VulnerabilitiesSchema,
  // Optional: without it the package is still tracked, but posture needs an explicit ?version=.
  latest: LatestVersionSchema.optional(),
});

export type WatchConfig = z.infer<typeof WatchConfigSchema>;
