import { config } from "../config/index.js";
import { GcsStorageBackend } from "./gcs.js";
import { LocalStorageBackend } from "./local.js";
import { StorageBackend } from "./types.js";

export function createStorageBackend(): StorageBackend {
  if (config.STORAGE_BACKEND === "gcs") {
    if (!config.GCS_BUCKET) {
      throw new Error("GCS_BUCKET is required when STORAGE_BACKEND=gcs");
    }
    return new GcsStorageBackend(config.GCS_BUCKET);
  }

  return new LocalStorageBackend(config.LOCAL_STORAGE_PATH);
}

export { StorageBackend, buildArtifactPath } from "./types.js";
export { LocalStorageBackend } from "./local.js";
export { GcsStorageBackend } from "./gcs.js";
