import { JSONPath } from "jsonpath-plus";
import { PackageConfig, Platform } from "../types/package-config.js";
import {
  DiscoveryStrategy,
  DiscoveredVersion,
  ArtifactInfo,
  DiscoveryOptions,
  PlatformKey,
  platformKey,
} from "./types.js";
import {
  applyTagPattern,
  parseVersion,
  extractVersionGroup,
  generateSortKey,
} from "../common/version-utils.js";
import { RetainableVersion, selectRetentionWindow } from "../common/retention-window.js";
import { log } from "../common/log.js";
import { fetchJsonWithRetry } from "../common/http.js";
import { config as appConfig } from "../config/index.js";

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

export class GitHubReleasesStrategy implements DiscoveryStrategy {
  async discoverVersions(
    config: PackageConfig,
    options: DiscoveryOptions = {},
  ): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "github-releases") {
      throw new Error('GitHubReleasesStrategy requires discovery.type = "github-releases"');
    }
    const { repo, include_prereleases, tag_pattern, asset_version_pattern, max_releases } =
      config.discovery;

    const releases = await this.fetchReleases(
      repo,
      options.maxReleases ?? max_releases,
      options.releasePage,
    );
    const ltsGroups = await this.extractLtsGroups(config, tag_pattern);
    const minVersion = config.versioning.min_version;

    if (asset_version_pattern) {
      return this.discoverByAssetVersion(
        config,
        releases,
        asset_version_pattern,
        include_prereleases,
        ltsGroups,
        options,
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

      // min_version is a *discovery* floor, applied before retention: a version below it is
      // never a candidate, so it cannot occupy a retention slot or have artifacts resolved.
      // This is what lets a config exclude releases that are structurally unservable — an
      // upstream that published no assets, or one predating the per-asset digests a package
      // relies on for checksums — rather than only trimming the tail of a healthy history.
      if (minVersion && generateSortKey(version) < generateSortKey(minVersion)) {
        log.debug({ version, minVersion }, "Version below min_version, skipping");
        continue;
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

    const targeted = options.versionGroups?.length
      ? candidates.filter((candidate) => options.versionGroups!.includes(candidate.versionGroup))
      : candidates;
    const retainedVersions = new Set(
      (options.historical ? targeted : this.applyRetentionPreFilter(targeted, config)).map(
        (c) => c.version,
      ),
    );

    // Resolve artifacts only for versions that survive retention; historical backfills resolve
    // every explicitly targeted candidate so an older fallback is not silently discarded.
    // This avoids "asset not found" noise for old releases that predate certain platforms.
    const discovered: DiscoveredVersion[] = [];
    for (const c of targeted) {
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
    options: DiscoveryOptions,
  ): DiscoveredVersion[] {
    const include_prereleases = includePrereleases;
    const regex = new RegExp(assetVersionPattern);
    const minVersion = config.versioning.min_version;

    // Two mappings per version, because in this mode a version is rebuilt into many releases:
    //   versionToRelease  → most-recent release containing it, used for {tag} in artifact URLs
    //   versionFirstSeen  → oldest release containing it, used as the release date
    // GitHub returns releases newest-first, so the first sighting is the newest and the last
    // sighting is the oldest.
    const versionToRelease = new Map<string, GitHubRelease>();
    const versionFirstSeen = new Map<string, GitHubRelease>();

    for (const release of releases) {
      if (release.draft) continue;
      if (!include_prereleases && release.prerelease) continue;

      for (const asset of release.assets) {
        const m = regex.exec(asset.name);
        if (!m || !m[1]) continue;
        const version = m[1];

        // Apply min_version filter. Sort keys, not raw strings: a byte-wise compare of
        // "3.9.1" against "3.11" says 3.9.1 is the greater of the two and lets it past a
        // 3.11 floor, because "9" > "1". Zero-padding each numeric segment is what makes the
        // comparison agree with version order.
        if (minVersion && generateSortKey(version) < generateSortKey(minVersion)) continue;

        if (!versionToRelease.has(version)) {
          versionToRelease.set(version, release);
        }
        versionFirstSeen.set(version, release);
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
      // Date the version by when it *first* appeared, not by the latest rebuild that shipped it.
      // Upstreams like python-build-standalone re-ship every maintained line in every dated
      // release, so the newest release's date would make a months-old patch look brand new — and
      // with cooling off enabled, a line that gets rebuilt more often than the embargo is long
      // would never become servable. Bounded by the fetched window: a version present in every
      // release we pulled is dated to the oldest one, which is an upper bound on its true age and
      // therefore errs towards "old enough to serve".
      const firstSeen = versionFirstSeen.get(version) ?? release;
      candidates.push({
        version,
        versionGroup,
        isLts: ltsGroups.has(versionGroup),
        releasedAt: firstSeen.published_at ? new Date(firstSeen.published_at) : undefined,
        release,
      });
    }

    const targeted = options.versionGroups?.length
      ? candidates.filter((candidate) => options.versionGroups!.includes(candidate.versionGroup))
      : candidates;
    const retainedVersions = new Set(
      (options.historical ? targeted : this.applyRetentionPreFilter(targeted, config)).map(
        (c) => c.version,
      ),
    );

    const discovered: DiscoveredVersion[] = [];
    for (const c of targeted) {
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

  /**
   * Which candidates are worth resolving artifact URLs for. Must keep everything the sync service
   * will keep — a version that survives the sync window but was skipped here reaches the database
   * with an empty artifact map, so it is neither downloadable nor retryable.
   *
   * Passing a null cooling-off threshold is exact for this strategy: every release carries a
   * published_at, so the embargo is always date-anchored and never falls back to the watermark.
   */
  private applyRetentionPreFilter<T extends RetainableVersion>(
    candidates: T[],
    config: PackageConfig,
  ): T[] {
    return selectRetentionWindow(candidates, config.retention);
  }

  private async fetchReleases(
    repo: string,
    maxReleases?: number,
    releasePage?: number,
  ): Promise<GitHubRelease[]> {
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "walrus/1.0",
    };
    // Read per request, not captured at module load: the schema normalises an empty secret to
    // undefined, and a value fixed at import time cannot be exercised by a test.
    if (appConfig.GITHUB_TOKEN) {
      headers["Authorization"] = `Bearer ${appConfig.GITHUB_TOKEN}`;
    }

    const perPage = Math.min(maxReleases ?? 100, 100);
    const page = releasePage ?? 1;
    const url = `${GITHUB_API_BASE}/repos/${repo}/releases?per_page=${perPage}&page=${page}`;
    return fetchJsonWithRetry<GitHubRelease[]>(url, { headers });
  }

  /**
   * The version groups to mark LTS.
   *
   * A GitHub release carries no LTS field of its own — the API has nowhere to put one — so
   * unlike `json-api` this strategy cannot read LTS off the release it is already looking at.
   * `lts_source = "api"` therefore names a separate document that says which lines are
   * long-term: for PowerShell that is the repo's own `tools/metadata.json`, whose
   * `LTSReleaseTag` Microsoft updates with every release.
   *
   * A failed LTS fetch propagates rather than degrading to "nothing is LTS". Silently
   * clearing the flag would persist a wrong answer — `is_lts` is written to the version row —
   * and a sync that loudly fails is recoverable in a way a quietly mislabelled estate is not.
   */
  private async extractLtsGroups(
    config: PackageConfig,
    tagPattern: string | undefined,
  ): Promise<Set<string>> {
    const { lts_support, lts_source, lts_groups, lts_api_url, lts_api_path, lts_api_shape } =
      config.versioning;
    if (!lts_support) return new Set();

    if (lts_source === "explicit" && lts_groups) return new Set(lts_groups);

    if (lts_source === "api" && lts_api_url && lts_api_path) {
      const data = await fetchJsonWithRetry<Record<string, unknown>>(lts_api_url, {
        headers: { "User-Agent": "walrus/1.0" },
      });
      const raw: unknown = JSONPath({ path: lts_api_path, json: data });
      const values = Array.isArray(raw) ? (raw as unknown[]).flat() : [];

      const groups = new Set<string>();
      for (const value of values) {
        const group =
          lts_api_shape === "tags"
            ? this.tagToVersionGroup(config, String(value), tagPattern)
            : String(value);
        if (group === null) {
          // One unparseable entry should not decide the LTS status of the whole package, but it
          // must not pass unremarked either: an upstream that changed its tag style would
          // otherwise just stop reporting LTS.
          log.warn(
            { value, lts_api_url, tagPattern },
            "LTS tag did not reduce to a version group, skipping",
          );
          continue;
        }
        groups.add(group);
      }
      return groups;
    }

    // "even_major" is declared in the schema but not implemented for this strategy; it would
    // need a predicate over groups rather than a set, since the groups are not known until
    // discovery has run. Nothing configures it today.
    return new Set();
  }

  /**
   * Reduce a release tag to a version group by the same two steps a discovered release takes,
   * so an LTS document and the discovery loop cannot disagree about what "7.6" means.
   */
  private tagToVersionGroup(
    config: PackageConfig,
    tag: string,
    tagPattern: string | undefined,
  ): string | null {
    const version = tagPattern ? applyTagPattern(tag, tagPattern) : parseVersion(tag);
    if (version === null) return null;
    return extractVersionGroup(version, config.versioning.version_group_extract);
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
        // The API's own byte count, preferred over the response's Content-Length when the
        // download checks for truncation (WAL-67).
        size: asset.size,
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
