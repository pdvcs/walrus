import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { Response, Router } from "express";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { getVersionAvailabilityStatus } from "../services/vuln-service.js";
import {
  decideWholeObjectTransfer,
  defaultTransferLimits,
  TransferLimits,
} from "../services/transfer-policy.js";
import { ByteRange } from "../storage/types.js";
import { ArtifactRow, VersionRow } from "../types/db.js";
import { parseRangeHeader } from "./range.js";

export interface DownloadRouteDeps {
  getVersion: (packageName: string, version: string) => Promise<VersionRow | null>;
  listAffectsForPackage: (packageName: string) => Promise<AffectsWithCveRow[]>;
  getArtifact: (versionId: number, os: string, arch: string) => Promise<ArtifactRow | null>;
  /** Omit `range` for the whole object; a range reads only those bytes from storage. */
  streamFromStorage: (key: string, range?: ByteRange) => Readable;
  /** Defaults to the configured limits; injected so tests can drive the threshold. */
  transferLimits?: TransferLimits;
  /**
   * Package row lookup for the enabled/tombstone check. Disabled packages — operator
   * disabled or TOML-removed tombstones (WAL-53) — must not serve binaries via direct
   * URL; the catalog listing routes already hide them. Optional so tests can omit it.
   */
  getPackageRow?: (packageName: string) => Promise<{ enabled: boolean } | null>;
}

export function createDownloadRouter(deps: DownloadRouteDeps): Router {
  const router = Router();

  router.get("/:package/:version/:os/:arch", async (req, res, next) => {
    try {
      const packageName = req.params.package;
      const version = req.params.version;
      const os = req.params.os;
      const arch = req.params.arch;

      // Disabled/tombstoned packages do not serve binaries, even with artifacts on
      // disk — direct URLs must not bypass the catalog (404, not 403: 403 is reserved
      // for the critical-CVE gate's "this version is dangerous" semantics).
      const pkgRow = await deps.getPackageRow?.(packageName);
      if (pkgRow && !pkgRow.enabled) {
        res.status(404).json({ error: `Package '${packageName}' is not available` });
        return;
      }

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
      if (!artifact) {
        res.status(404).json({ error: "Artifact not found" });
        return;
      }

      // Policy checks run before the availability check: an artifact inside its release embargo is
      // deliberately left `pending` with no gcs_path (the sync service skips queueing its
      // download), so testing availability first would report every cooling-off artifact as a 404.
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

      if (artifact.status !== "available" || !artifact.gcs_path) {
        res.status(404).json({ error: "Artifact not found" });
        return;
      }

      // Everything below here serves bytes, and everything above decided whether any bytes may
      // be served at all. A ranged request passes the same gates as a full one — there is
      // deliberately no path that hands out part of an artifact a 200 would have refused.
      const etag = artifactEtag(artifact);
      res.setHeader("Accept-Ranges", "bytes");
      res.setHeader("ETag", etag);

      // A client resuming against an artifact that has been re-downloaded since must not splice
      // two different builds together. An If-Range that does not match the current entity means:
      // ignore the range, send the whole thing, let the client start over. A date-form If-Range
      // is treated the same way — the conservative direction.
      const ifRange = req.headers["if-range"];
      const rangeIsUsable = ifRange === undefined || ifRange === etag;

      // With no recorded size there is no way to answer a range correctly: Content-Range has to
      // state the total, and a 416 would claim the object is empty. Ignore the header instead,
      // which RFC 9110 permits.
      const requested =
        rangeIsUsable && artifact.file_size !== null
          ? parseRangeHeader(req.headers.range, artifact.file_size)
          : ({ kind: "none" } as const);

      if (requested.kind === "unsatisfiable") {
        res.setHeader("Content-Range", `bytes */${artifact.file_size ?? 0}`);
        res.status(416).json({ error: "Requested range not satisfiable" });
        return;
      }

      if (requested.kind === "single") {
        setEntityHeaders(res, artifact);
        res.setHeader(
          "Content-Range",
          `bytes ${requested.start}-${requested.end}/${artifact.file_size}`,
        );
        res.status(206);
        const range = { start: requested.start, end: requested.end };
        await streamToResponse(deps.streamFromStorage(artifact.gcs_path, range), res);
        return;
      }

      // No range, or one walrus answers with the full representation (RFC 9110 permits that for
      // multi-range). Either way this is a whole-object transfer, which is what the size policy
      // governs.
      const decision = decideWholeObjectTransfer(
        artifact.file_size,
        deps.transferLimits ?? defaultTransferLimits,
      );
      if (decision.kind === "refuse") {
        res.status(decision.status).json(decision.body);
        return;
      }

      setEntityHeaders(res, artifact);
      res.status(200);
      await streamToResponse(deps.streamFromStorage(artifact.gcs_path), res);
    } catch (err) {
      next(err);
    }
  });

  return router;
}

/**
 * Headers that describe the artifact itself. Set only on responses that carry its bytes — a
 * refusal or a 416 is a JSON error, and `Content-Disposition: attachment` on one would have a
 * browser save the error to disk.
 */
function setEntityHeaders(res: Response, artifact: ArtifactRow): void {
  res.setHeader("Content-Type", "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${artifact.filename}"`);
  // Do NOT set Content-Length: Cloud Run buffers HTTP/1.1 responses when Content-Length
  // is present, hitting its 32 MB response size limit for large artifacts.
  // Without Content-Length, Node.js uses chunked transfer encoding, which Cloud Run streams.
  //
  // The same holds for a 206, and for the same reason: the client chooses the chunk size, so a
  // Content-Length would silently cap a usable chunk at 32 MB. Content-Range already states
  // exactly how many bytes the response carries, so nothing is lost by omitting it.
  if (artifact.file_size !== null) {
    // The whole object's size, on a 206 as well — it is what a client reassembling the artifact
    // needs, and it is deliberately not the length of this response.
    res.setHeader("X-Content-Length", String(artifact.file_size));
  }

  if (artifact.checksum && artifact.checksum_type) {
    // Always the digest of the *whole* artifact. A client verifies after reassembly, never per
    // chunk.
    const checksumType = artifact.checksum_type.toLowerCase();
    if (checksumType === "sha256") {
      res.setHeader("X-Checksum-Sha256", artifact.checksum);
    }
    if (checksumType === "sha1") {
      res.setHeader("X-Checksum-Sha1", artifact.checksum);
    }
  }
}

async function streamToResponse(source: Readable, res: Response): Promise<void> {
  try {
    await pipeline(source, res);
  } catch (streamErr) {
    res.destroy(streamErr instanceof Error ? streamErr : new Error(String(streamErr)));
  }
}

/**
 * A validator for `If-Range`. The checksum is the artifact's identity when there is one: a
 * re-download that changes the bytes changes the digest, so a client resuming across a re-sync
 * is told to start over instead of splicing two builds. Without a checksum, the completion
 * timestamp does the same job — it moves whenever the object is rewritten.
 */
function artifactEtag(artifact: ArtifactRow): string {
  if (artifact.checksum) {
    return `"${artifact.checksum_type ?? "sum"}-${artifact.checksum}"`;
  }
  const writtenAt = artifact.download_completed_at?.getTime() ?? 0;
  return `"${artifact.id}-${artifact.file_size ?? 0}-${writtenAt}"`;
}
