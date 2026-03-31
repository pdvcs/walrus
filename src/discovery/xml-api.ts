import { XMLParser } from "fast-xml-parser";
import { JSONPath } from "jsonpath-plus";
import { PackageConfig } from "../types/package-config.js";
import {
  DiscoveryStrategy,
  DiscoveredVersion,
  ArtifactInfo,
  PlatformKey,
  platformKey,
} from "./types.js";
import { applyTagPattern, extractVersionGroup } from "../common/version-utils.js";
import { fetchWithRetry, fetchJsonWithRetry } from "../common/http.js";
import { log } from "../common/log.js";
import semver from "semver";

function applyTemplate(template: string, vars: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(vars)) {
    result = result.replaceAll(`{${key}}`, value);
  }
  return result;
}

/** Parse a timestamp value that may be Unix ms (number) or ISO 8601 (string). */
function parseTimestamp(value: unknown): Date | undefined {
  if (typeof value === "number") {
    // Heuristic: values > 1e10 are milliseconds, otherwise seconds
    const ms = value > 1e10 ? value : value * 1000;
    const d = new Date(ms);
    return isNaN(d.getTime()) ? undefined : d;
  }
  if (typeof value === "string" && value) {
    const d = new Date(value);
    return isNaN(d.getTime()) ? undefined : d;
  }
  return undefined;
}

const xmlParser = new XMLParser({ isArray: () => false });

/**
 * XML metadata strategy: fetches an XML document, parses it, and navigates to
 * a version list using JSONPath (same navigation approach as json-api).
 *
 * Artifact URLs are constructed from platform.url_template using {version} and {ext}.
 * Checksum URLs are constructed from checksum.url_template (type = "separate-file").
 *
 * Optionally fetches per-version release timestamps via release_date_url_template +
 * release_date_path (e.g. Maven Central Solr search API).
 */
export class XmlApiStrategy implements DiscoveryStrategy {
  async discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "xml-api") {
      throw new Error('XmlApiStrategy requires discovery.type = "xml-api"');
    }

    const {
      url,
      versions_path,
      version_filter,
      tag_pattern,
      release_date_url_template,
      release_date_path,
    } = config.discovery;

    const response = await fetchWithRetry(url, { headers: { "User-Agent": "walrus/1.0" } });
    const text = await response.text();
    const parsed = xmlParser.parse(text) as Record<string, unknown>;

    const raw: unknown = JSONPath({ path: versions_path, json: parsed });
    const rawVersions = Array.isArray(raw) ? (raw as unknown[]).flat() : [];

    const filterRegex = version_filter ? new RegExp(version_filter) : null;
    const { min_version } = config.versioning;

    // Build the list of candidate versions (filtering, tag_pattern, min_version)
    const versions: string[] = [];
    for (const rawVer of rawVersions) {
      if (typeof rawVer !== "string" || !rawVer) continue;
      let version = rawVer;
      if (filterRegex && !filterRegex.test(version)) continue;
      if (tag_pattern) {
        const extracted = applyTagPattern(version, tag_pattern);
        if (extracted === null) continue;
        version = extracted;
      }
      if (min_version && semver.valid(version) && semver.valid(min_version)) {
        if (semver.lt(version, min_version)) continue;
      }
      versions.push(version);
    }

    // Fetch release timestamps in parallel (one call per version)
    const releaseDates = await this.fetchReleaseDates(
      versions,
      release_date_url_template,
      release_date_path,
    );

    const discovered: DiscoveredVersion[] = [];

    for (const version of versions) {
      const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
      if (versionGroup === null) {
        log.debug({ version }, "xml-api: skipping version (no group match)");
        continue;
      }

      const artifacts = new Map<PlatformKey, ArtifactInfo>();

      for (const platform of config.platforms) {
        if (!platform.url_template) {
          log.warn(
            { version, platform: platformKey(platform) },
            "xml-api platform missing url_template, skipping",
          );
          continue;
        }

        const vars = {
          version,
          ext: platform.extension,
          os: platform.os_upstream,
          arch: platform.arch_upstream,
        };

        const artifactUrl = applyTemplate(platform.url_template, vars);
        const filename = artifactUrl.split("/").at(-1) ?? `artifact.${platform.extension}`;

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

      if (artifacts.size === 0) {
        log.debug({ version }, "xml-api: skipping version (no artifacts)");
        continue;
      }

      discovered.push({
        version,
        versionGroup,
        isLts: false,
        artifacts,
        releasedAt: releaseDates.get(version),
      });
    }

    return discovered;
  }

  private async fetchReleaseDates(
    versions: string[],
    urlTemplate: string | undefined,
    datePath: string | undefined,
  ): Promise<Map<string, Date>> {
    const result = new Map<string, Date>();
    if (!urlTemplate || !datePath) return result;

    await Promise.all(
      versions.map(async (version) => {
        const url = urlTemplate.replaceAll("{version}", version);
        try {
          const data = await fetchJsonWithRetry<Record<string, unknown>>(url, {
            headers: { "User-Agent": "walrus/1.0" },
          });
          const raw: unknown = JSONPath({ path: datePath, json: data, wrap: false });
          const date = parseTimestamp(raw);
          if (date) result.set(version, date);
        } catch (err) {
          log.warn({ version, url, error: String(err) }, "xml-api: failed to fetch release date");
        }
      }),
    );

    return result;
  }
}
