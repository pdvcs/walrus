import semver from "semver";
import { PackageConfig } from "../types/package-config.js";
import {
  DiscoveryStrategy,
  DiscoveredVersion,
  ArtifactInfo,
  PlatformKey,
  platformKey,
} from "./types.js";
import { extractVersionGroup } from "../common/version-utils.js";
import { fetchWithRetry } from "../common/http.js";
import { log } from "../common/log.js";

/**
 * Directory-listing strategy — a version-list-only source for upstreams that expose a browsable
 * HTTP directory but no structured API.
 *
 * The `pattern` regex is applied to the whole response body, and its first capture group yields a
 * version string. The matched link is only a source of *versions*; it is never assumed to be the
 * artifact URL, because the listing host and the download host are frequently different services
 * (PostgreSQL's release history lives on `ftp.postgresql.org` while its binaries are served from
 * EnterpriseDB's CDN). Each `[[platforms]]` block therefore builds its own download URL from
 * `url_template`, the same construction `json-api` and `xml-api` use — pinned by the schema, which
 * requires `url_template` on every platform when this type is selected.
 *
 * No release date is parsed from the listing (Apache autoindex exposes a `Last-Modified` column,
 * but reading it is out of scope); `releasedAt` stays undefined and cooling-off anchors to
 * `versions.discovered_at` through the existing WAL-91 fallback path.
 */

/** Substitute {version}/{os}/{arch}/{ext} placeholders in a URL or filename template. */
function applyTemplate(template: string, vars: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(vars)) {
    result = result.replaceAll(`{${key}}`, value);
  }
  return result;
}

/** A three-component semver string, coercing partial versions ("18.6" -> "18.6.0"). */
function coerceSemver(version: string): string | null {
  return semver.valid(version) ?? semver.coerce(version)?.version ?? null;
}

export class DirectoryListingStrategy implements DiscoveryStrategy {
  async discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "directory-listing") {
      throw new Error('DirectoryListingStrategy requires discovery.type = "directory-listing"');
    }

    const { url, pattern } = config.discovery;

    const response = await fetchWithRetry(url, { headers: { "User-Agent": "walrus/1.0" } });
    const body = await response.text();

    const versions = this.extractVersions(body, pattern, config.versioning.min_version);
    if (versions.length === 0) {
      log.warn({ url, pattern }, "directory-listing: pattern matched no versions");
      return [];
    }

    const discovered: DiscoveredVersion[] = [];
    for (const version of versions) {
      const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
      if (versionGroup === null) {
        log.debug({ version }, "directory-listing: skipping version (no group match)");
        continue;
      }

      const artifacts = new Map<PlatformKey, ArtifactInfo>();
      for (const platform of config.platforms) {
        if (!platform.url_template) {
          // The schema guarantees this; thrown here so a hand-built PackageConfig fails loudly
          // rather than serving a version with no artifact.
          throw new Error(
            `directory-listing platform ${platformKey(platform)} is missing url_template`,
          );
        }

        const vars = {
          version,
          os: platform.os_upstream,
          arch: platform.arch_upstream,
          ext: platform.extension,
        };
        const artifactUrl = applyTemplate(platform.url_template, vars);
        const filename = platform.filename_template
          ? applyTemplate(platform.filename_template, vars)
          : (artifactUrl.split("/").at(-1) ?? `artifact.${platform.extension}`);

        let checksumUrl: string | undefined;
        let checksumType: string | undefined;
        if (config.checksum?.type === "separate-file" && config.checksum.url_template) {
          checksumUrl = applyTemplate(config.checksum.url_template, vars);
          checksumType = config.checksum.algorithm;
        }

        artifacts.set(platformKey(platform), {
          url: artifactUrl,
          filename,
          checksumUrl,
          checksumType,
        });
      }

      discovered.push({ version, versionGroup, isLts: false, artifacts });
    }

    return discovered;
  }

  /** Extract unique version strings from the listing body, filter by `min_version`, newest first. */
  private extractVersions(body: string, pattern: string, minVersion?: string): string[] {
    // "g" is required by matchAll; the pattern is a user-supplied regex without flags.
    const regex = new RegExp(pattern, "g");
    const found = new Set<string>();
    for (const match of body.matchAll(regex)) {
      if (match[1]) found.add(match[1]);
    }

    const min = minVersion ? coerceSemver(minVersion) : null;
    const filtered = [...found].filter((version) => {
      if (!min) return true;
      const coerced = coerceSemver(version);
      return coerced !== null && semver.gte(coerced, min);
    });

    return filtered.sort((a, b) =>
      semver.rcompare(coerceSemver(a) ?? "0.0.0", coerceSemver(b) ?? "0.0.0"),
    );
  }
}
