import { z } from "zod";
import { VulnerabilitiesSchema } from "./package-config.js";

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
 */
export const WatchConfigSchema = z.object({
  name: z.string().regex(/^[a-z][a-z0-9-]*$/, "Name must be lowercase alphanumeric with hyphens"),
  display_name: z.string(),
  vendor: z.string(),
  website: z.string().optional(),
  description: z.string().optional(),
  // Required here (unlike on PackageConfig): a watch entry with no vuln config
  // would create a package row that does nothing at all.
  vulnerabilities: VulnerabilitiesSchema,
});

export type WatchConfig = z.infer<typeof WatchConfigSchema>;
