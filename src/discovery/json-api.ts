import { JSONPath } from "jsonpath-plus";
import { PackageConfig, Platform } from "../types/package-config.js";
import {
  DiscoveryStrategy,
  DiscoveredVersion,
  ArtifactInfo,
  PlatformKey,
  platformKey,
} from "./types.js";
import { applyTagPattern, parseVersion, extractVersionGroup } from "../common/version-utils.js";
import { log } from "../common/log.js";
import { fetchJsonWithRetry, fetchWithRetry, HttpRequestError } from "../common/http.js";

/** Safely coerce an unknown API value to string; returns '' for objects/null/undefined. */
function str(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return "";
}

/** Normalize compact YYYYMMDDHHmmss+ZZZZ timestamps (e.g. Gradle buildTime) to ISO 8601. */
function normalizeDateString(v: string): string {
  const m = v.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})([+-]\d{4})$/);
  if (m) return `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${m[7]}`;
  return v;
}

/** Parse an ISO 8601 string (or compact YYYYMMDDHHmmss+ZZZZ) into a Date. */
function parseDate(v: unknown): Date | undefined {
  if (typeof v !== "string" || !v) return undefined;
  const d = new Date(normalizeDateString(v));
  return isNaN(d.getTime()) ? undefined : d;
}

export class JsonApiStrategy implements DiscoveryStrategy {
  async discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "json-api") {
      throw new Error('JsonApiStrategy requires discovery.type = "json-api"');
    }

    const { release_url_template } = config.discovery;

    if (!release_url_template) {
      return this.discoverInline(config);
    } else {
      return this.discoverTwoStep(config);
    }
  }

  /** Inline submode: single API call returns versions + artifacts together */
  private async discoverInline(config: PackageConfig): Promise<DiscoveredVersion[]> {
    const discovery = config.discovery;
    if (discovery.type !== "json-api") throw new Error("wrong type");

    const {
      url,
      releases_path,
      release_version_field,
      release_date_field,
      release_download_url_field,
      tag_pattern,
      files_field,
      file_os_field,
      file_arch_field,
      file_kind_field,
      file_kind_value,
      file_filename_field,
      file_url_base,
      file_checksum_field,
      release_lts_field,
    } = discovery;

    if (!url || !releases_path || !release_version_field) {
      throw new Error("Inline json-api requires url, releases_path, release_version_field");
    }

    const data = await fetchJsonWithRetry<Record<string, unknown>>(url, {
      headers: { "User-Agent": "walrus/1.0" },
    });
    const releases: unknown = JSONPath({ path: releases_path, json: data });
    if (!Array.isArray(releases)) {
      throw new Error(`releases_path "${releases_path}" did not return an array`);
    }

    const discovered: DiscoveredVersion[] = [];

    for (const release of releases) {
      const releaseObj = release as Record<string, unknown>;
      const rawVer = releaseObj[release_version_field];
      if (typeof rawVer !== "string" || !rawVer) continue;
      let version = rawVer;

      if (tag_pattern) {
        const extracted = applyTagPattern(version, tag_pattern);
        if (extracted === null) continue;
        version = extracted;
      } else {
        version = parseVersion(version);
      }

      const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
      if (versionGroup === null) continue;

      const artifacts = new Map<PlatformKey, ArtifactInfo>();

      if (files_field) {
        // Nested-files mode: each release contains an array of per-platform artifacts
        const rawFiles = releaseObj[files_field];
        const files = Array.isArray(rawFiles) ? (rawFiles as unknown[]) : [];

        for (const platform of config.platforms) {
          if (platform.url_template) {
            // String-list mode: files array is platform identifier strings (e.g. Node.js).
            // Check if os_upstream string appears in the list, then construct URL from template.
            const available = files.some((f) => f === platform.os_upstream);
            if (!available) continue;

            const fileUrl = platform.url_template.replace(/\{version\}/g, version);
            const filename = fileUrl.split("/").at(-1) ?? "";

            artifacts.set(platformKey(platform), {
              url: fileUrl,
              filename,
              checksum: undefined,
              checksumType: undefined,
            });
          } else {
            // Object mode: files array contains objects with os/arch/filename fields (e.g. Go).
            const file = files.find((f: unknown) => {
              const obj = f as Record<string, string>;
              const osMatch = file_os_field ? obj[file_os_field] === platform.os_upstream : true;
              const archMatch = file_arch_field
                ? obj[file_arch_field] === platform.arch_upstream
                : true;
              const kindMatch =
                file_kind_field && file_kind_value
                  ? obj[file_kind_field] === file_kind_value
                  : true;
              return osMatch && archMatch && kindMatch;
            }) as Record<string, string> | undefined;

            if (!file) continue;

            const filename = file_filename_field ? file[file_filename_field] : undefined;
            if (!filename) continue;

            const url_base = file_url_base ?? "";
            const fileUrl = url_base + filename;
            const checksum = file_checksum_field ? file[file_checksum_field] : undefined;

            artifacts.set(platformKey(platform), {
              url: fileUrl,
              filename,
              checksum,
              checksumType: checksum ? "sha256" : undefined,
            });
          }
        }
      } else {
        // Flat mode: single platform-independent download URL on the release object itself
        const releaseUrl = release_download_url_field
          ? str(releaseObj[release_download_url_field])
          : "";
        if (!releaseUrl) continue;

        const filename = releaseUrl.split("/").at(-1) ?? "";
        const checksum = file_checksum_field ? str(releaseObj[file_checksum_field]) : undefined;

        for (const platform of config.platforms) {
          artifacts.set(platformKey(platform), {
            url: releaseUrl,
            filename,
            checksum: checksum || undefined,
            checksumType: checksum ? "sha256" : undefined,
          });
        }
      }

      const releasedAt = release_date_field ? parseDate(releaseObj[release_date_field]) : undefined;
      const rawLts = release_lts_field ? releaseObj[release_lts_field] : undefined;
      const isLts = typeof rawLts === "string" && rawLts.length > 0;

      discovered.push({
        version,
        versionGroup,
        isLts,
        artifacts,
        releasedAt,
      });
    }

    return discovered;
  }

  /** Two-step submode: fetch version list, then per-version API call */
  private async discoverTwoStep(config: PackageConfig): Promise<DiscoveredVersion[]> {
    const discovery = config.discovery;
    if (discovery.type !== "json-api") throw new Error("wrong type");

    const { url, versions_path, release_url_template, explicit_versions } = discovery;
    if (!release_url_template) {
      throw new Error("Two-step json-api requires release_url_template");
    }

    // LTS groups — populated from API or explicit config
    const ltsGroups = new Set<string>();

    let majorVersions: number[];

    if (explicit_versions) {
      majorVersions = explicit_versions;
    } else {
      if (!url || !versions_path) {
        throw new Error("Two-step json-api requires either explicit_versions or url+versions_path");
      }
      const data = await fetchJsonWithRetry<Record<string, unknown>>(url, {
        headers: { "User-Agent": "walrus/1.0" },
      });

      // Extract LTS groups from the version-list API response
      if (
        config.versioning.lts_support &&
        config.versioning.lts_source === "api" &&
        config.versioning.lts_api_path &&
        !config.versioning.lts_api_url
      ) {
        const ltsRaw: unknown = JSONPath({ path: config.versioning.lts_api_path, json: data });
        const ltsList = Array.isArray(ltsRaw) ? (ltsRaw as unknown[]).flat() : [];
        for (const v of ltsList) ltsGroups.add(String(v));
      }

      const versionListRaw: unknown = JSONPath({ path: versions_path, json: data });
      if (!Array.isArray(versionListRaw)) {
        throw new Error(`versions_path "${versions_path}" did not return an array`);
      }
      // Deduplicate — URL-based version lists can have repeated major versions
      majorVersions = [...new Set<number>((versionListRaw as number[]).flat())];
    }

    // LTS from a dedicated API URL (used when explicit_versions is set, or as an override)
    if (
      config.versioning.lts_support &&
      config.versioning.lts_source === "api" &&
      config.versioning.lts_api_url &&
      config.versioning.lts_api_path
    ) {
      const ltsData = await fetchJsonWithRetry<Record<string, unknown>>(
        config.versioning.lts_api_url,
        { headers: { "User-Agent": "walrus/1.0" } },
      );
      const ltsRaw: unknown = JSONPath({ path: config.versioning.lts_api_path, json: ltsData });
      const ltsList = Array.isArray(ltsRaw) ? (ltsRaw as unknown[]).flat() : [];
      for (const v of ltsList) ltsGroups.add(String(v));
    }

    // LTS from explicit lts_groups config
    if (
      config.versioning.lts_support &&
      config.versioning.lts_source === "explicit" &&
      config.versioning.lts_groups
    ) {
      for (const g of config.versioning.lts_groups) ltsGroups.add(g);
    }

    const discovered: DiscoveredVersion[] = [];

    for (const majorVersion of majorVersions) {
      for (const platform of config.platforms) {
        const releaseUrl = release_url_template
          .replace("{major_version}", String(majorVersion))
          .replace("{arch}", platform.arch_upstream)
          .replace("{os}", platform.os_upstream)
          .replace("{page_size}", String(config.retention.versions_per_group));

        try {
          const relData = await this.fetchReleaseData(releaseUrl);
          const versions = this.extractVersionsFromRelease(
            relData,
            config,
            platform,
            ltsGroups,
            String(majorVersion),
          );

          for (const v of versions) {
            const existing = discovered.find((d) => d.version === v.version);
            if (existing) {
              // Merge artifact info for this platform
              for (const [key, art] of v.artifacts) {
                existing.artifacts.set(key, art);
              }
            } else {
              discovered.push(v);
            }
          }
        } catch (err) {
          log.warn({ releaseUrl, error: String(err) }, "Failed to fetch release data");
        }
      }
    }

    return discovered;
  }

  private async fetchReleaseData(url: string): Promise<unknown[]> {
    const response = await fetchWithRetry(
      url,
      { headers: { "User-Agent": "walrus/1.0" } },
      { maxRetries: 1 },
    ).catch((err: unknown) => {
      if (err instanceof HttpRequestError && err.status === 404) {
        return null;
      }
      throw err;
    });
    if (response === null) {
      return [];
    }
    const data: unknown = await response.json();
    return Array.isArray(data) ? (data as unknown[]) : [data];
  }

  private extractVersionsFromRelease(
    data: unknown[],
    config: PackageConfig,
    platform: Platform,
    ltsGroups: Set<string>,
    majorVersion: string,
  ): DiscoveredVersion[] {
    const discovery = config.discovery;
    if (discovery.type !== "json-api") throw new Error("wrong type");

    const { release_download_url_field, release_filename_field, release_date_field } = discovery;
    const results: DiscoveredVersion[] = [];

    for (const item of data) {
      const obj = item as Record<string, unknown>;
      const releasedAt = release_date_field ? parseDate(obj[release_date_field]) : undefined;

      // Filter by name_must_contain if specified (e.g. to exclude musl Linux builds)
      if (platform.name_must_contain) {
        const nameVal =
          obj["name"] ?? (release_filename_field ? obj[release_filename_field] : undefined);
        const name = typeof nameVal === "string" ? nameVal : "";
        if (!name.includes(platform.name_must_contain)) continue;
      }

      let semverStr: string;

      // Azul-style: java_version is [major, minor, patch] array
      const javaVersionArr = obj["java_version"];
      if (Array.isArray(javaVersionArr) && javaVersionArr.length >= 3) {
        const build = obj["openjdk_build_number"] ?? 0;
        semverStr = `${javaVersionArr[0] as number}.${javaVersionArr[1] as number}.${javaVersionArr[2] as number}+${build as number}`;
      } else {
        // Adoptium-style: binary is nested under binaries[0]
        const binary = (obj["binaries"] as Record<string, unknown>[])?.[0] ?? obj;
        const versionData = obj["version_data"] as Record<string, unknown> | undefined;
        if (versionData) {
          semverStr = `${versionData["major"] as number}.${versionData["minor"] as number}.${versionData["security"] as number}+${versionData["build"] as number}`;
        } else {
          const relName = obj["release_name"];
          semverStr = typeof relName === "string" ? relName : majorVersion;
        }
        // Adoptium package path
        const packagePath = binary["package"] as Record<string, unknown> | undefined;
        if (!packagePath) continue;
        const downloadUrl = str(packagePath["link"]);
        const filename = str(packagePath["name"]);
        const checksum = packagePath["checksum"] as string | undefined;
        const versionGroup = extractVersionGroup(
          semverStr,
          config.versioning.version_group_extract,
        );
        if (!versionGroup) continue;
        const artifactMap = new Map<PlatformKey, ArtifactInfo>();
        artifactMap.set(platformKey(platform), {
          url: downloadUrl,
          filename,
          checksum,
          checksumType: checksum ? "sha256" : undefined,
        });
        results.push({
          version: semverStr,
          versionGroup,
          isLts: ltsGroups.has(majorVersion),
          artifacts: artifactMap,
          releasedAt,
        });
        continue;
      }

      const versionGroup = extractVersionGroup(semverStr, config.versioning.version_group_extract);
      if (!versionGroup) continue;

      // Resolve download URL and filename using configurable field names or Azul defaults
      const rawUrl = release_download_url_field
        ? obj[release_download_url_field]
        : obj["download_url"];
      const downloadUrl = str(rawUrl);
      const rawFilename = release_filename_field ? obj[release_filename_field] : obj["name"];
      const filename = str(rawFilename);
      if (!downloadUrl || !filename) continue;

      const artifactMap = new Map<PlatformKey, ArtifactInfo>();
      artifactMap.set(platformKey(platform), {
        url: downloadUrl,
        filename,
        checksum: undefined,
        checksumType: undefined,
      });

      results.push({
        version: semverStr,
        versionGroup,
        isLts: ltsGroups.has(majorVersion),
        artifacts: artifactMap,
        releasedAt,
      });
    }

    return results;
  }
}
