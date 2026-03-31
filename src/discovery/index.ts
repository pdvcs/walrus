import { PackageConfig } from "../types/package-config.js";
import { DiscoveryStrategy } from "./types.js";
import { GitHubReleasesStrategy } from "./github-releases.js";
import { JsonApiStrategy } from "./json-api.js";
import { DirectoryListingStrategy } from "./directory-listing.js";
import { XmlApiStrategy } from "./xml-api.js";

export function getStrategy(config: PackageConfig): DiscoveryStrategy {
  switch (config.discovery.type) {
    case "github-releases":
      return new GitHubReleasesStrategy();
    case "json-api":
      return new JsonApiStrategy();
    case "xml-api":
      return new XmlApiStrategy();
    case "directory-listing":
      return new DirectoryListingStrategy();
    default:
      throw new Error(`Unknown discovery type: ${(config.discovery as { type: string }).type}`);
  }
}

export { DiscoveryStrategy, DiscoveredVersion, ArtifactInfo, platformKey } from "./types.js";
