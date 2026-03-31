import { PackageConfig, Platform } from "../types/package-config.js";
import {
  DiscoveryStrategy,
  DiscoveredVersion,
  ArtifactInfo,
  PlatformKey,
  platformKey,
} from "./types.js";
import {
  applyTagPattern,
  parseVersion,
  extractVersionGroup,
  sortVersionsDesc,
} from "../common/version-utils.js";
import { log } from "../common/log.js";
import { fetchJsonWithRetry } from "../common/http.js";

interface GitHubRelease {
  tag_name: string;
  prerelease: boolean;
  draft: boolean;
  published_at: string | null;
  assets: GitHubAsset[];
}

interface GitHubAsset {
  name: string;
  browser_download_url: string;
  size: number;
  digest?: string; // "sha256:abc123..." — present in GitHub API v3 responses
}

const GITHUB_API_BASE = "https://api.github.com";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;

export class GitHubReleasesStrategy implements DiscoveryStrategy {
  async discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "github-releases") {
      throw new Error('GitHubReleasesStrategy requires discovery.type = "github-releases"');
    }
    const { repo, include_prereleases, tag_pattern, asset_version_pattern, max_releases } = config.discovery;

    const releases = await this.fetchReleases(repo, max_releases);
    const ltsGroups = this.extractLtsGroups(config, releases);

    if (asset_version_pattern) {
      return this.discoverByAssetVersion(
        config,
        releases,
        asset_version_pattern,
        include_prereleases,
        ltsGroups,
      );
    }

    // First pass: collect version metadata without resolving artifacts
    type Candidate = {
      version: string;
      versionGroup: string;
      isLts: boolean;
      releasedAt: Date | undefined;
      release: GitHubRelease;
    };
    const candidates: Candidate[] = [];

    for (const release of releases) {
      if (release.draft) continue;
      if (!include_prereleases && release.prerelease) continue;

      let version = release.tag_name;

      if (tag_pattern) {
        const extracted = applyTagPattern(version, tag_pattern);
        if (extracted === null) {
          log.debug({ tag: version, pattern: tag_pattern }, "Tag does not match pattern, skipping");
          continue;
        }
        version = extracted;
      } else {
        version = parseVersion(version);
      }

      const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
      if (versionGroup === null) {
        log.debug({ version }, "Could not extract version group, skipping");
        continue;
      }

      candidates.push({
        version,
        versionGroup,
        isLts: ltsGroups.has(versionGroup),
        releasedAt: release.published_at ? new Date(release.published_at) : undefined,
        release,
      });
    }

    // Resolve artifacts only for versions that survive retention; pruned versions get empty maps.
    // This avoids "asset not found" noise for old releases that predate certain platforms.
    const retainedVersions = new Set(
      this.applyRetentionPreFilter(candidates, config).map((c) => c.version),
    );

    const discovered: DiscoveredVersion[] = [];
    for (const c of candidates) {
      const artifacts = retainedVersions.has(c.version)
        ? this.resolveArtifacts(config, c.release, c.version)
        : new Map<PlatformKey, ArtifactInfo>();
      discovered.push({
        version: c.version,
        versionGroup: c.versionGroup,
        isLts: c.isLts,
        artifacts,
        releasedAt: c.releasedAt,
      });
    }

    return discovered;
  }

  /**
   * Asset-pivot mode: version is extracted from each asset filename, not the release tag.
   * One DiscoveredVersion is emitted per unique (version, versionGroup) combination seen
   * across all releases. {tag} in filename_template is replaced with the release tag_name.
   */
  private discoverByAssetVersion(
    config: PackageConfig,
    releases: GitHubRelease[],
    assetVersionPattern: string,
    includePrereleases: boolean,
    ltsGroups: Set<string>,
  ): DiscoveredVersion[] {
    const include_prereleases = includePrereleases;
    const regex = new RegExp(assetVersionPattern);
    const minVersion = config.versioning.min_version;

    // Collect candidate (version → most-recent release that contains it)
    // GitHub returns releases newest-first; first time we see a version wins.
    const versionToRelease = new Map<string, GitHubRelease>();

    for (const release of releases) {
      if (release.draft) continue;
      if (!include_prereleases && release.prerelease) continue;

      for (const asset of release.assets) {
        const m = regex.exec(asset.name);
        if (!m || !m[1]) continue;
        const version = m[1];

        // Apply min_version filter
        if (minVersion) {
          const parsed = parseVersion(version);
          const parsedMin = parseVersion(minVersion);
          if (parsed < parsedMin) continue;
        }

        if (!versionToRelease.has(version)) {
          versionToRelease.set(version, release);
        }
      }
    }

    // Build candidates keyed on extracted version
    type Candidate = {
      version: string;
      versionGroup: string;
      isLts: boolean;
      releasedAt: Date | undefined;
      release: GitHubRelease;
    };
    const candidates: Candidate[] = [];

    for (const [version, release] of versionToRelease) {
      const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
      if (versionGroup === null) {
        log.debug({ version }, "Could not extract version group, skipping");
        continue;
      }
      candidates.push({
        version,
        versionGroup,
        isLts: ltsGroups.has(versionGroup),
        releasedAt: release.published_at ? new Date(release.published_at) : undefined,
        release,
      });
    }

    const retainedVersions = new Set(
      this.applyRetentionPreFilter(candidates, config).map((c) => c.version),
    );

    const discovered: DiscoveredVersion[] = [];
    for (const c of candidates) {
      const artifacts = retainedVersions.has(c.version)
        ? this.resolveArtifacts(config, c.release, c.version, c.release.tag_name)
        : new Map<PlatformKey, ArtifactInfo>();
      discovered.push({
        version: c.version,
        versionGroup: c.versionGroup,
        isLts: c.isLts,
        artifacts,
        releasedAt: c.releasedAt,
      });
    }

    return discovered;
  }

  private applyRetentionPreFilter<T extends { version: string; versionGroup: string }>(
    candidates: T[],
    config: PackageConfig,
  ): T[] {
    const { versions_per_group, groups_to_keep } = config.retention;

    // Group candidates — GitHub API returns newest-first so order within each group is preserved
    const byGroup = new Map<string, T[]>();
    for (const c of candidates) {
      if (!byGroup.has(c.versionGroup)) byGroup.set(c.versionGroup, []);
      byGroup.get(c.versionGroup)!.push(c);
    }

    const sortedGroups = sortVersionsDesc([...byGroup.keys()]);
    const kept: T[] = [];

    for (let i = 0; i < sortedGroups.length; i++) {
      if (groups_to_keep !== undefined && i >= groups_to_keep) break;
      kept.push(...byGroup.get(sortedGroups[i])!.slice(0, versions_per_group));
    }

    return kept;
  }

  private async fetchReleases(repo: string, maxReleases?: number): Promise<GitHubRelease[]> {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "walrus/1.0",
    };
    if (GITHUB_TOKEN) {
      headers["Authorization"] = `Bearer ${GITHUB_TOKEN}`;
    }

    const perPage = Math.min(maxReleases ?? 100, 100);
    const url = `${GITHUB_API_BASE}/repos/${repo}/releases?per_page=${perPage}`;
    return fetchJsonWithRetry<GitHubRelease[]>(url, { headers });
  }

  private extractLtsGroups(config: PackageConfig, _releases: GitHubRelease[]): Set<string> {
    // GitHub releases strategy doesn't typically carry LTS data in the API response
    // This would be handled by 'even_major' or 'explicit' lts_source
    const { lts_support, lts_source, lts_groups } = config.versioning;
    if (!lts_support) return new Set();
    if (lts_source === "explicit" && lts_groups) return new Set(lts_groups);
    if (lts_source === "even_major") {
      // We don't know which versions exist yet without more context;
      // mark LTS at group-resolution time via version_group_extract
      // For now return a predicate-based approach via a special class
      // Actually we need all groups — caller handles this post-discovery
      return new Set();
    }
    return new Set();
  }

  private resolveArtifacts(
    config: PackageConfig,
    release: GitHubRelease,
    version: string,
    tag?: string,
  ): Map<PlatformKey, ArtifactInfo> {
    const artifacts = new Map<PlatformKey, ArtifactInfo>();

    for (const platform of config.platforms) {
      const filename = this.buildFilename(platform, version, tag);
      if (!filename) continue;

      const asset = release.assets.find((a) => a.name === filename);
      if (!asset) {
        log.debug({ filename, version }, "Asset not found in release");
        continue;
      }

      const info: ArtifactInfo = {
        url: asset.browser_download_url,
        filename: asset.name,
      };

      if (config.checksum?.type === "github-asset" && config.checksum.asset_suffix) {
        // Checksum is a sidecar file attached to the release
        const checksumAsset = release.assets.find(
          (a) => a.name === filename + config.checksum!.asset_suffix,
        );
        if (checksumAsset) {
          info.checksumUrl = checksumAsset.browser_download_url;
          info.checksumType = config.checksum.algorithm ?? "sha256";
        }
      } else if (config.checksum?.type === "github-asset-digest" && asset.digest) {
        // Checksum comes from the `digest` field on the asset object ("sha256:hex...")
        const colonIdx = asset.digest.indexOf(":");
        info.checksum = colonIdx >= 0 ? asset.digest.slice(colonIdx + 1) : asset.digest;
        info.checksumType = config.checksum.algorithm ?? "sha256";
      }

      artifacts.set(platformKey(platform), info);
    }

    return artifacts;
  }

  private buildFilename(platform: Platform, version: string, tag?: string): string | null {
    const template = platform.filename_template ?? platform.url_template;
    if (!template) return null;

    let result = template
      .replace("{arch}", platform.arch_upstream)
      .replace("{os}", platform.os_upstream)
      .replace("{ext}", platform.extension)
      .replace("{version}", version);

    if (tag !== undefined) {
      result = result.replace("{tag}", tag);
    }

    return result;
  }
}
