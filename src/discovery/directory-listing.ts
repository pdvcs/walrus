import { PackageConfig } from "../types/package-config.js";
import { DiscoveryStrategy, DiscoveredVersion } from "./types.js";

/** Stub implementation — lower priority, add when needed */
export class DirectoryListingStrategy implements DiscoveryStrategy {
  discoverVersions(_config: PackageConfig): Promise<DiscoveredVersion[]> {
    return Promise.reject(new Error("DirectoryListingStrategy is not yet implemented"));
  }
}
