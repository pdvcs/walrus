import { PackageConfig, Platform } from "../types/package-config.js";

export type PlatformKey = `${string}/${string}`; // e.g. "linux/x86-64"

export interface ArtifactInfo {
  url: string;
  filename: string;
  checksum?: string; // actual hex digest (known at discovery time, e.g. inline-api)
  checksumUrl?: string; // URL to fetch the digest from (e.g. github-asset .sha256 file)
  checksumType?: string;
}

export interface DiscoveredVersion {
  version: string; // Full version string after tag_pattern applied
  versionGroup: string; // Extracted retention bucket
  isLts: boolean;
  artifacts: Map<PlatformKey, ArtifactInfo>;
  releasedAt?: Date; // Upstream publish timestamp, when known
}

export interface DiscoveryStrategy {
  discoverVersions(config: PackageConfig): Promise<DiscoveredVersion[]>;
}

export function platformKey(platform: Platform): PlatformKey {
  return `${platform.os}/${platform.arch}`;
}
