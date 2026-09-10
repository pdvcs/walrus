import { XMLParser } from "fast-xml-parser";
import TOML from "@iarna/toml";
import semver from "semver";
import { PackageConfig, Platform } from "../types/package-config.js";
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
 * Rust distribution manifests are TOML, not JSON, and rust-lang/rust attaches no assets to its
 * GitHub Releases. The channel manifest is the only machine-readable source of artifact URLs and
 * their SHA256 hashes, so this strategy reads it directly:
 *
 *   1. enumerate archived `channel-rust-{version}.toml` keys from the S3 list API,
 *   2. fetch the newest `max_versions` manifests,
 *   3. read `[pkg.<package>].target.<triple>` for the gzip (`url`/`hash`) or xz (`xz_url`/`xz_hash`)
 *      artifact of each configured platform.
 *
 * The platform's canonical `os`/`arch` are combined into the Rust target triple as
 * `{arch_upstream}-{os_upstream}` (e.g. `x86_64` + `unknown-linux-gnu`), and `extension` chooses
 * between the gzip and xz artifacts. Walrus streams whatever it stores, so neither format needs
 * walrus-side decompression.
 */

/** One manifest key in the bucket listing, e.g. "dist/channel-rust-1.98.0.toml". */
const MANIFEST_KEY_PATTERN = /^dist\/channel-rust-(\d+\.\d+\.\d+)\.toml$/;

/** The version embedded in `[pkg.<name>].version`, which carries a trailing " (hash date)". */
const MANIFEST_VERSION_PATTERN = /^(\d+\.\d+\.\d+)/;

const DEFAULT_MAX_VERSIONS = 10;

/** Defensive bound on listing pagination; the bucket holds a few hundred keys at most. */
const MAX_LIST_PAGES = 20;

/** `Contents` repeats in a ListBucketResult, so it must always parse as an array. */
const listingParser = new XMLParser({ isArray: (name) => name === "Contents" });

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

/** The Rust target triple a platform's config encodes: arch first, then the OS portion. */
function targetTriple(platform: Platform): string {
  return `${platform.arch_upstream}-${platform.os_upstream}`;
}

/** Pick the gzip or xz artifact from a target block, according to the platform's extension. */
function selectArtifact(
  target: Record<string, unknown>,
  extension: string,
): { url: string; hash: string } | null {
  const xz = extension === "tar.xz";
  const url = str(xz ? target.xz_url : target.url);
  if (!url) return null;
  return { url, hash: str(xz ? target.xz_hash : target.hash) };
}

/** The manifest's top-level release date, e.g. "2026-09-03". */
function parseManifestDate(value: unknown): Date | undefined {
  const raw = str(value);
  if (!raw) return undefined;
  const parsed = new Date(raw);
  return isNaN(parsed.getTime()) ? undefined : parsed;
}

export class RustChannelStrategy implements DiscoveryStrategy {
  async discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "rust-channel") {
      throw new Error('RustChannelStrategy requires discovery.type = "rust-channel"');
    }

    const {
      listing_url,
      manifest_url_template,
      max_versions,
      package: packageName,
    } = config.discovery;

    const versions = await this.listManifestVersions(config, listing_url);
    if (versions.length === 0) {
      log.warn({ listing_url }, "rust-channel: no archived manifests found");
      return [];
    }

    const candidates = versions.slice(0, max_versions ?? DEFAULT_MAX_VERSIONS);
    const discovered: DiscoveredVersion[] = [];

    for (const version of candidates) {
      const manifestUrl = manifest_url_template.replaceAll("{version}", version);
      try {
        const result = await this.discoverOne(config, version, manifestUrl, packageName);
        if (result) discovered.push(result);
      } catch (err) {
        log.warn(
          { version, manifestUrl, error: String(err) },
          "rust-channel: failed to read manifest",
        );
      }
    }

    // The listing is sorted newest-first; re-sort after manifest versions (the authoritative
    // value) may differ from the key's version, and drop any gap created by a skipped manifest.
    discovered.sort((a, b) => semver.rcompare(a.version, b.version));
    return discovered;
  }

  /** Enumerate the manifest keys and return the matching versions, newest first. */
  private async listManifestVersions(config: PackageConfig, listingUrl: string): Promise<string[]> {
    const found = new Set<string>();
    let nextUrl: string | null = listingUrl;

    for (let page = 0; page < MAX_LIST_PAGES && nextUrl; page += 1) {
      const currentUrl = nextUrl;
      const response = await fetchWithRetry(currentUrl, {
        headers: { "User-Agent": "walrus/1.0" },
      });
      const parsed = listingParser.parse(await response.text()) as Record<string, unknown>;
      const root = isRecord(parsed.ListBucketResult) ? parsed.ListBucketResult : {};
      const contents = Array.isArray(root.Contents) ? root.Contents : [];

      for (const item of contents) {
        const key = isRecord(item) ? str(item.Key) : "";
        const match = key.match(MANIFEST_KEY_PATTERN);
        if (match) found.add(match[1]);
      }

      const truncated = root.IsTruncated === true || root.IsTruncated === "true";
      const token = str(root.NextContinuationToken);
      if (!truncated || !token) {
        nextUrl = null;
      } else {
        const next = new URL(listingUrl);
        next.searchParams.set("continuation-token", token);
        nextUrl = next.toString();
      }
    }

    const minVersion = config.versioning.min_version;
    // min_version may be a prefix like "1.90"; coerce to a full semver before comparing, or
    // semver throws on the partial form. Manifests always carry three components.
    const min = minVersion
      ? (semver.valid(minVersion) ?? semver.coerce(minVersion)?.version)
      : null;
    return [...found]
      .filter((version) => !min || semver.gte(version, min))
      .sort((a, b) => semver.rcompare(a, b));
  }

  /** Read one version's manifest into a DiscoveredVersion, or null when it has nothing to serve. */
  private async discoverOne(
    config: PackageConfig,
    listedVersion: string,
    manifestUrl: string,
    packageName: string,
  ): Promise<DiscoveredVersion | null> {
    const response = await fetchWithRetry(manifestUrl, {
      headers: { "User-Agent": "walrus/1.0" },
    });
    const manifest = TOML.parse(await response.text()) as unknown as Record<string, unknown>;

    const pkg =
      isRecord(manifest.pkg) && isRecord(manifest.pkg[packageName])
        ? manifest.pkg[packageName]
        : {};

    // The manifest's own version is authoritative; fall back to the version named by the key.
    const versionMatch = MANIFEST_VERSION_PATTERN.exec(str(pkg.version));
    const version = versionMatch ? versionMatch[1] : listedVersion;

    const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
    if (versionGroup === null) {
      log.debug({ version }, "rust-channel: version did not match version_group_extract");
      return null;
    }

    const targets = isRecord(pkg.target) ? pkg.target : {};
    const artifacts = new Map<PlatformKey, ArtifactInfo>();

    for (const platform of config.platforms) {
      const triple = targetTriple(platform);
      const target = isRecord(targets[triple]) ? targets[triple] : undefined;
      if (!target || target.available !== true) {
        log.warn(
          { version, platform: platformKey(platform), triple },
          "rust-channel: target unavailable in manifest, skipping",
        );
        continue;
      }

      const artifact = selectArtifact(target, platform.extension);
      if (!artifact) {
        log.warn(
          { version, platform: platformKey(platform), triple, extension: platform.extension },
          "rust-channel: manifest has no artifact for the configured extension, skipping",
        );
        continue;
      }

      const filename = artifact.url.split("/").at(-1) ?? "";
      if (!filename) continue;

      artifacts.set(platformKey(platform), {
        url: artifact.url,
        filename,
        checksum: artifact.hash || undefined,
        checksumType: artifact.hash ? "sha256" : undefined,
      });
    }

    if (artifacts.size === 0) {
      log.debug({ version }, "rust-channel: no artifacts resolved, skipping version");
      return null;
    }

    return {
      version,
      versionGroup,
      isLts: false,
      artifacts,
      releasedAt: parseManifestDate(manifest.date),
    };
  }
}
