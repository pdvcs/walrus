import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { Router } from "express";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { getVersionAvailabilityStatus } from "../services/vuln-service.js";
import { ArtifactRow, VersionRow } from "../types/db.js";

export interface DownloadRouteDeps {
  getVersion: (packageName: string, version: string) => Promise<VersionRow | null>;
  listAffectsForPackage: (packageName: string) => Promise<AffectsWithCveRow[]>;
  getArtifact: (versionId: number, os: string, arch: string) => Promise<ArtifactRow | null>;
  streamFromStorage: (key: string) => Readable;
}

export function createDownloadRouter(deps: DownloadRouteDeps): Router {
  const router = Router();

  router.get("/:package/:version/:os/:arch", async (req, res, next) => {
    try {
      const packageName = req.params.package;
      const version = req.params.version;
      const os = req.params.os;
      const arch = req.params.arch;

      const versionRow = await deps.getVersion(packageName, version);
      if (!versionRow) {
        res.status(404).json({ error: "Version not found" });
        return;
      }

      const affects = await deps.listAffectsForPackage(packageName);
      if (getVersionAvailabilityStatus(versionRow.version, affects) === "blocked") {
        res.status(403).json({ error: "Version blocked due to a critical vulnerability" });
        return;
      }

      const artifact = await deps.getArtifact(versionRow.id, os, arch);
      if (!artifact || artifact.status !== "available" || !artifact.gcs_path) {
        res.status(404).json({ error: "Artifact not found" });
        return;
      }

      if (artifact.cooling_off_until !== null && artifact.cooling_off_until > new Date()) {
        const retryAfterSecs = Math.ceil(
          (artifact.cooling_off_until.getTime() - Date.now()) / 1000,
        );
        res.setHeader("Retry-After", String(retryAfterSecs));
        res.status(423).json({
          error: "Artifact is in cooling off period",
          available_at: artifact.cooling_off_until.toISOString(),
        });
        return;
      }

      const fileStream = deps.streamFromStorage(artifact.gcs_path);

      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename="${artifact.filename}"`);
      // Do NOT set Content-Length: Cloud Run buffers HTTP/1.1 responses when Content-Length
      // is present, hitting its 32 MB response size limit for large artifacts.
      // Without Content-Length, Node.js uses chunked transfer encoding, which Cloud Run streams.
      if (artifact.file_size !== null) {
        res.setHeader("X-Content-Length", String(artifact.file_size));
      }

      if (artifact.checksum && artifact.checksum_type) {
        const checksumType = artifact.checksum_type.toLowerCase();
        if (checksumType === "sha256") {
          res.setHeader("X-Checksum-Sha256", artifact.checksum);
        }
        if (checksumType === "sha1") {
          res.setHeader("X-Checksum-Sha1", artifact.checksum);
        }
      }

      res.status(200);
      try {
        await pipeline(fileStream, res);
      } catch (streamErr) {
        res.destroy(streamErr instanceof Error ? streamErr : new Error(String(streamErr)));
      }
    } catch (err) {
      next(err);
    }
  });

  return router;
}
