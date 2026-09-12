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
 * .NET publishes no usable assets on GitHub Releases, but it does ship a machine-readable
 * channel document at `dotnet/core/release-notes/<channel>/releases.json`:
 *
 *   releases[]        one entry per patch release, newest first, each carrying
 *                     `release-date`, `sdk` (the current SDK), `sdks[]` (every active
 *                     feature band at that release), `runtime`, `aspnetcore-runtime`
 *                     and `windowsdesktop`.
 *   <component>.files[]  `{ name, rid, url, hash }`, where `hash` is SHA-512.
 *
 * The source of truth is one document per channel, so this strategy fetches each configured
 * channel document once and flattens it (`url` may name several channels — the hosting bundle
 * spans 8.0 and 10.0):
 *
 *   - `component = "sdk"` yields one DiscoveredVersion per `sdks[]` entry. Each SDK embeds
 *     a runtime version under `runtime-version`, carried out as `cveVersion` (ADR-008
 *     generalised): .NET CVEs are filed against the runtime, not the SDK.
 *   - `component = "runtime" | "aspnetcore-runtime"` yields one DiscoveredVersion per
 *     release from that component's `version`/`files`.
 *
 * A platform selects files by `rid` (the platform's `os_upstream`), extension and, when
 * set, `name_must_contain`. Binaries and installers share a rid and differ only by
 * filename, so the extension is what excludes the installer. The served filename is the
 * URL tail, which carries the version the `name` field omits.
 */
export class DotnetReleasesStrategy implements DiscoveryStrategy {
  async discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]> {
    if (config.discovery.type !== "dotnet-releases") {
      throw new Error('DotnetReleasesStrategy requires discovery.type = "dotnet-releases"');
    }

    const { url, component } = config.discovery;
    const urls = Array.isArray(url) ? url : [url];
    const documents = await Promise.all(
      urls.map((channelUrl) =>
        fetchWithRetry(channelUrl, { headers: { "User-Agent": "walrus/1.0" } }).then((response) =>
          response.json(),
        ),
      ),
    );
    const releases = documents.flatMap(releasesFrom);

    const discovered: DiscoveredVersion[] = [];
    for (const release of releases) {
      const entries = componentEntries(release, component);
      for (const entry of entries) {
        const result = this.discoverOne(config, release, entry);
        if (result) discovered.push(result);
      }
    }

    // `releases[]` is newest-first, but a release's `sdks[]` names several feature bands and
    // the bands interleave across releases, so the assembled order is not monotonic. Re-sort
    // on the authoritative version. Keep the first occurrence when a version repeats, since
    // the newest release carries the freshest runtime mapping.
    const seen = new Set<string>();
    return discovered
      .filter((v) => {
        if (seen.has(v.version)) return false;
        seen.add(v.version);
        return true;
      })
      .sort((a, b) => semver.rcompare(a.version, b.version));
  }

  /** Read one release entry into a DiscoveredVersion, or null when it has nothing to serve. */
  private discoverOne(
    config: PackageConfig,
    release: Record<string, unknown>,
    entry: Record<string, unknown>,
  ): DiscoveredVersion | null {
    const version = str(entry.version);
    if (!version) return null;

    const versionGroup = extractVersionGroup(version, config.versioning.version_group_extract);
    if (versionGroup === null) {
      log.debug({ version }, "dotnet-releases: version did not match version_group_extract");
      return null;
    }

    const files = Array.isArray(entry.files) ? entry.files : [];
    const artifacts = new Map<PlatformKey, ArtifactInfo>();

    for (const platform of config.platforms) {
      const file = selectFile(files, platform);
      if (!file) {
        log.warn(
          { version, platform: platformKey(platform), rid: platform.os_upstream },
          "dotnet-releases: no matching file for platform, skipping",
        );
        continue;
      }

      const filename = file.url.split("/").at(-1) ?? "";
      if (!filename) continue;

      artifacts.set(platformKey(platform), {
        url: file.url,
        filename,
        checksum: file.hash || undefined,
        checksumType: file.hash ? "sha512" : undefined,
      });
    }

    if (artifacts.size === 0) {
      log.debug({ version }, "dotnet-releases: no artifacts resolved, skipping version");
      return null;
    }

    return {
      version,
      versionGroup,
      isLts: false,
      artifacts,
      releasedAt: parseDate(release["release-date"]),
      cveVersion: str(entry["runtime-version"]) || undefined,
    };
  }
}

function releasesFrom(document: unknown): Record<string, unknown>[] {
  if (!isRecord(document) || !Array.isArray(document.releases)) return [];
  return document.releases.filter(isRecord);
}

/**
 * The version-bearing objects for one release. The SDK component lives in `sdks[]` (falling
 * back to the singular `sdk` for a malformed/older document); every other component is a
 * single object keyed by its own name.
 */
function componentEntries(
  release: Record<string, unknown>,
  component: "sdk" | "runtime" | "aspnetcore-runtime",
): Record<string, unknown>[] {
  if (component === "sdk") {
    const sdks = release.sdks;
    if (Array.isArray(sdks)) return sdks.filter(isRecord);
    return isRecord(release.sdk) ? [release.sdk] : [];
  }
  return isRecord(release[component]) ? [release[component]] : [];
}

interface DotnetFile {
  name: string;
  rid: string;
  url: string;
  hash: string;
}

/** The file a platform wants: matching rid, extension and optional name substring. */
function selectFile(
  files: unknown[],
  platform: PackageConfig["platforms"][number],
): DotnetFile | null {
  const suffix = `.${platform.extension}`;
  for (const raw of files) {
    if (!isRecord(raw)) continue;
    const file: DotnetFile = {
      name: str(raw.name),
      rid: str(raw.rid),
      url: str(raw.url),
      hash: str(raw.hash),
    };
    if (file.rid !== platform.os_upstream) continue;
    if (!file.name.endsWith(suffix)) continue;
    if (platform.name_must_contain && !file.name.includes(platform.name_must_contain)) continue;
    if (!file.url) continue;
    return file;
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return "";
}

function parseDate(value: unknown): Date | undefined {
  const raw = str(value);
  if (!raw) return undefined;
  const parsed = new Date(raw);
  return isNaN(parsed.getTime()) ? undefined : parsed;
}
