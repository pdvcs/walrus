import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { Response, Router } from "express";
import { log } from "../common/log.js";
import { AffectsWithCveRow } from "../db/queries/cves.js";
import { BlockingCveMatch, findBlockingCveMatch } from "../services/vuln-service.js";
import { z } from "zod";
import { BlockedVersionErrorSchema } from "./schemas.js";
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
      const blocking = findBlockingCveMatch(versionRow.version, affects);
      if (blocking !== null) {
        res.status(403).json(blockedVersionBody(versionRow.version, blocking));
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
      //
      // "Send the whole thing" is unavailable above the size threshold, though, so the mismatch
      // has to survive as far as the refusal and be named there — otherwise the one mechanism
      // protecting a resumed download from splicing is unreportable on precisely the artifacts
      // large enough to be resumed across processes (WAL-66 AC16).
      const ifRange = req.headers["if-range"];
      const rangeIsUsable = ifRange === undefined || ifRange === etag;
      const staleValidator = !rangeIsUsable && req.headers.range !== undefined;

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
        staleValidator ? "stale-validator" : "no-range",
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
 * The gate's refusal, explained (WAL-79).
 *
 * The reason is not recomputed here: `findBlockingCveMatch` produced it while deciding, and
 * re-running the match to recover a string would let the explanation drift from the decision it
 * explains. Everything below is a projection of that one result.
 *
 * `error` is written to stand alone. A build fails in CI, someone reads one line of JSON out of a
 * log, and that line has to be enough to act on — so it names the CVE and, when the advisory says
 * so, the version to move to. The rest of the story is in `blocked_by`.
 */
function blockedVersionBody(version: string, blocking: BlockingCveMatch): BlockedVersionError {
  const cve = blocking.cve;
  try {
    const score = firstScore(cve);
    const qualifier =
      score !== null ? `CVSS ${score}` : (cve.severity?.toLowerCase() ?? "critical");
    const remedy = cve.fixed_in ? ` — fixed in ${cve.fixed_in}` : "";
    return BlockedVersionErrorSchema.parse({
      error: `Version ${version} is blocked by ${cve.cve_id} (${qualifier})${remedy}`,
      blocked_by: {
        cve_id: cve.cve_id,
        // Every matching branch of `evaluateRange` produces a non-empty reason, so this default
        // is unreachable today. It is here because the field is a string the response promises
        // and the gate must not depend on that promise holding.
        matched_because: blocking.matched_because || "matched a known critical CVE range",
        // `?? null` rather than a bare read: a nullable field's schema rejects `undefined`, so a
        // row that simply omits a key would otherwise cost the whole explanation.
        severity: cve.severity ?? null,
        severity_source: cve.severity_source ?? null,
        cvss_v3_score: toScore(cve.cvss_v3_score),
        cvss_v4_score: toScore(cve.cvss_v4_score),
        cvss_v2_score: toScore(cve.cvss_v2_score),
        is_kev: cve.is_kev === true,
        fixed_in: cve.fixed_in ?? null,
      },
    });
  } catch (err) {
    // The decision to refuse was already made and is not revisited here; only its description
    // failed. Everywhere else a schema mismatch should surface as a 500 in dev and tests
    // (that is the point of parsing responses), but not on this one: a 500 tells a client
    // walrus is broken and the request is worth retrying, about a version walrus withheld on
    // purpose. Loud in the logs, unchanged on the wire.
    log.error(
      { err, version, cve_id: cve.cve_id },
      "Could not describe a critical-CVE block; refusing with the generic message",
    );
    return { error: GENERIC_BLOCK_MESSAGE };
  }
}

type BlockedVersionError = z.infer<typeof BlockedVersionErrorSchema>;

/**
 * The pre-WAL-79 body, kept as the floor rather than deleted. `blockedVersionBody` returns the
 * schema's own type, so a future required field this fallback cannot supply is a compile error
 * there rather than a 500 in production.
 */
const GENERIC_BLOCK_MESSAGE = "Version blocked due to a critical vulnerability";

/** Scores arrive as strings from pg NUMERIC columns; the schema and the message want numbers. */
function toScore(value: number | string | null | undefined): number | null {
  if (value === null || value === undefined) return null;
  const score = Number(value);
  return Number.isNaN(score) ? null : score;
}

/**
 * The score to quote in the one-line message: v3 by preference because it is what most readers
 * recognise, then v4, then v2. Which version it came from is in `severity_source`, and all three
 * are in the body — this is only choosing what fits on a line.
 */
function firstScore(cve: BlockingCveMatch["cve"]): number | null {
  for (const raw of [cve.cvss_v3_score, cve.cvss_v4_score, cve.cvss_v2_score]) {
    const score = toScore(raw);
    if (score !== null) return score;
  }
  return null;
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
