import { TransformConfig, Platform } from "../types/package-config.js";
import { ArchiveTransform, TransformResultMeta } from "./types.js";
import { TarBz2ToZipTransform, TAR_BZ2_TO_ZIP_ID } from "./tar-bz2-to-zip.js";

export { TAR_BZ2_TO_ZIP_ID };
export type { ArchiveTransform, TransformResultMeta } from "./types.js";

// Keyed by the family name a config writes in `[platforms.transform].type`; the versioned
// identity lives on the implementation (`ArchiveTransform.id`). One implementation per
// family at a time — a behavioural change ships as a new identity, not a fork of the map.
const registry: Record<string, ArchiveTransform> = {
  "tar-bz2-to-zip": new TarBz2ToZipTransform(),
};

export function getTransform(type: string): ArchiveTransform {
  const transform = registry[type];
  if (!transform) {
    throw new Error(
      `unknown transform type '${type}' — known: ${Object.keys(registry).join(", ")}`,
    );
  }
  return transform;
}

/**
 * The post-transform gate (WAL-57 AC5): enforced by the caller after the transform completes
 * and before the artifact reaches `available`. Returns the problems found; an empty list
 * means the output is fit to serve.
 */
export function checkGate(meta: TransformResultMeta, config: TransformConfig): string[] {
  const problems: string[] = [];
  if (meta.pathsMissing.length > 0) {
    problems.push(`transform output is missing required path(s): ${meta.pathsMissing.join(", ")}`);
  }
  if (config.min_entries !== undefined && meta.entryCount < config.min_entries) {
    problems.push(
      `transform output holds ${meta.entryCount} entr${meta.entryCount === 1 ? "y" : "ies"}, ` +
        `below the required minimum of ${config.min_entries}`,
    );
  }
  return problems;
}

/**
 * The filename the artifact is served under — the transform's output, not what upstream
 * published. `{version}`, `{os}` and `{arch}` are walrus's canonical values here, because a
 * served name describes walrus's catalogue, not upstream's; `{ext}` is the transform's own
 * extension. Without a template, the upstream filename keeps its stem and takes the
 * transform's extension.
 */
export function renderServedFilename(
  transform: TransformConfig,
  platform: Pick<Platform, "os" | "arch" | "extension">,
  version: string,
  upstreamFilename: string,
): string {
  if (transform.filename_template) {
    return transform.filename_template
      .replaceAll("{version}", version)
      .replaceAll("{os}", platform.os)
      .replaceAll("{arch}", platform.arch)
      .replaceAll("{ext}", transform.extension);
  }
  const stem = upstreamFilename.endsWith(`.${platform.extension}`)
    ? upstreamFilename.slice(0, -(platform.extension.length + 1))
    : upstreamFilename;
  return `${stem}.${transform.extension}`;
}
