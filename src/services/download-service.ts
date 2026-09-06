import crypto from "crypto";
import { Readable, Transform } from "stream";
import { Pool } from "pg";
import { updateArtifactStatus } from "../db/queries/artifacts.js";
import { ArtifactRow } from "../types/db.js";
import { StorageBackend } from "../storage/types.js";
import { config } from "../config/index.js";
import { TransformConfig } from "../types/package-config.js";
import { getTransform, checkGate } from "../transform/index.js";
import { TransformResultMeta } from "../transform/types.js";
import { Semaphore } from "../common/semaphore.js";
import { log } from "../common/log.js";
import { createEgressFetch } from "../common/http.js";

export type ChecksumAlgorithm = "sha256" | "sha1";

export interface DownloadRequest {
  artifactId: number;
  upstreamUrl: string;
  storagePath: string;
  expectedChecksum?: string;
  checksumUrl?: string; // URL to fetch the expected checksum from (e.g. .sha256 sidecar)
  checksumType?: ChecksumAlgorithm;
  /**
   * Byte count the upstream API advertises for this artifact, where it publishes one. Takes
   * precedence over the response's own `Content-Length`, being the independent number — but
   * like it, is not compared against a content-coded response (see `advertisedSourceSize`).
   */
  expectedSize?: number;
  /**
   * Repackage the upstream stream before it reaches storage (WAL-57). The upstream digest
   * and advertised size describe the *source* bytes; the artifact's own checksum and size
   * come out of the pipeline's other end. Absent = store upstream bytes verbatim, exactly
   * as before the transform stage existed.
   */
  transform?: TransformConfig;
}

export interface ArtifactStatusRepo {
  updateArtifactStatus: typeof updateArtifactStatus;
}

export interface DownloadServiceOptions {
  fetchImpl?: typeof fetch;
  /** Retries *after* the first attempt. Defaults to `DOWNLOAD_MAX_ATTEMPTS - 1`. */
  maxRetries?: number;
  statusRepo?: ArtifactStatusRepo;
  /**
   * Bounds how many transformed artifacts are in flight at once, shared across every
   * DownloadService in the process (WAL-61 AC2). Defaults to a module-level semaphore sized
   * by TRANSFORM_CONCURRENCY; plain downloads never take a permit.
   */
  transformSemaphore?: Semaphore;
}

/**
 * What a dry-run transform exercise (WAL-59) observed. The full pipeline ran for real —
 * fetch, hash, transform, gate — against the injected no-op storage, so nothing persisted
 * and this is the whole report.
 */
export interface TransformReport {
  transform: string;
  entryCount: number;
  outputSize: number;
  outputChecksum: string;
  requirePathsPresent: string[];
  requirePathsMissing: string[];
  /** Symlinks the config explicitly allowed dropping; a drop is recorded, never silent. */
  droppedSymlinks: string[];
}

export interface DownloadResult {
  status: ArtifactRow["status"] | "skipped";
  attempts: number;
  storagePath?: string;
  fileSize?: number;
  checksum?: string;
  /** Provenance of the source bytes (WAL-58); present only when a transform ran. */
  sourceChecksum?: string;
  sourceFileSize?: number;
  transform?: string;
  transformReport?: TransformReport;
  error?: string;
}

/** Shared process-wide bound on concurrent transforms (WAL-61 AC2). */
const sharedTransformSemaphore = new Semaphore(config.TRANSFORM_CONCURRENCY);

export class DownloadService {
  private readonly fetchImpl: typeof fetch;
  /**
   * Egress rules (WAL-113) can restrict by `purpose`, and artifact bytes and checksum
   * sidecars are different rows in the plan's egress table — so each gets its own default
   * `createEgressFetch()` instance. A test-injected `opts.fetchImpl` still overrides both with
   * the same mock, exactly as before this split (WAL-112).
   */
  private readonly checksumFetchImpl: typeof fetch;
  private readonly maxRetries: number;
  private readonly statusRepo: ArtifactStatusRepo;
  private readonly transformSemaphore: Semaphore;

  constructor(
    private readonly pool: Pool,
    private readonly storage: StorageBackend,
    opts: DownloadServiceOptions = {},
  ) {
    this.fetchImpl = opts.fetchImpl ?? createEgressFetch({ purpose: "artifact" });
    this.checksumFetchImpl = opts.fetchImpl ?? createEgressFetch({ purpose: "checksum" });
    this.maxRetries = opts.maxRetries ?? config.DOWNLOAD_MAX_ATTEMPTS - 1;
    this.statusRepo = opts.statusRepo ?? { updateArtifactStatus };
    this.transformSemaphore = opts.transformSemaphore ?? sharedTransformSemaphore;
  }

  async downloadArtifact(req: DownloadRequest, dryRun = false): Promise<DownloadResult> {
    // Dry-run keeps its old shape for every download walrus would skip storing; only a
    // transform makes it worth fetching upstream bytes to a null sink (WAL-59) — validate is
    // the caller that wants that, and it injects the no-op storage itself.
    if (dryRun && !req.transform) {
      return { status: "skipped", attempts: 0 };
    }

    if (!dryRun) {
      await this.statusRepo.updateArtifactStatus(this.pool, req.artifactId, {
        status: "downloading",
        download_started_at: new Date(),
        error_message: null,
      });
    }

    const algorithm = req.checksumType ?? "sha256";
    const maxAttempts = this.maxRetries + 1;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      // A transform is CPU-bound with live decompression and deflate state per artifact, so
      // it holds one permit for the whole pipeline (WAL-61 AC2). Plain downloads never ask.
      const releaseTransform =
        req.transform !== undefined ? await this.transformSemaphore.acquire() : () => {};
      try {
        const result = await this.attemptDownload(req, dryRun, algorithm, attempt);
        return result;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        // The delete on the failure path is unconditional, not mismatch-only: a transform
        // can die mid-stream after a partial upload has begun, and the retry overwrites the
        // same key while `status` stays failed, so nothing half-written is ever served.
        await Promise.resolve(this.storage.delete(req.storagePath)).catch(() => {});
        if (attempt < maxAttempts) {
          continue;
        }
      } finally {
        releaseTransform();
      }
    }

    if (!dryRun) {
      await this.statusRepo.updateArtifactStatus(this.pool, req.artifactId, {
        status: "failed",
        error_message: lastError?.message ?? "download failed",
        download_completed_at: new Date(),
      });
    }

    return {
      status: "failed",
      attempts: maxAttempts,
      error: lastError?.message ?? "download failed",
    };
  }

  private async attemptDownload(
    req: DownloadRequest,
    dryRun: boolean,
    algorithm: ChecksumAlgorithm,
    attempt: number,
  ): Promise<DownloadResult> {
    const transformer = req.transform ? getTransform(req.transform.type) : null;

    const response = await this.fetchImpl(req.upstreamUrl);
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} from ${req.upstreamUrl}`);
    }

    if (!response.body) {
      throw new Error(`Empty response body from ${req.upstreamUrl}`);
    }

    // Hash of the SOURCE bytes — what upstream published, and what its digest describes.
    const sourceHash = crypto.createHash(algorithm);
    let sourceSize = 0;
    const sourceHashTransform = new Transform({
      transform(chunk: Buffer, _enc, cb) {
        sourceHash.update(chunk);
        sourceSize += chunk.length;
        cb(null, chunk);
      },
    });

    let sink: Readable = sourceHashTransform;
    let outputHash: crypto.Hash | null = null;
    let outputSize = 0;
    let transformMeta: Promise<TransformResultMeta> | null = null;

    if (transformer && req.transform) {
      const transformed = transformer.apply(sourceHashTransform, req.transform);
      transformMeta = transformed.meta;
      outputHash = crypto.createHash(algorithm);
      const outputHashTransform = new Transform({
        transform(chunk: Buffer, _enc, cb) {
          outputHash!.update(chunk);
          outputSize += chunk.length;
          cb(null, chunk);
        },
      });
      transformed.output.on("error", (err) => outputHashTransform.destroy(err));
      transformed.output.pipe(outputHashTransform);
      sink = outputHashTransform;
    }

    const nodeStream = Readable.fromWeb(response.body);
    nodeStream.on("error", (err) => sourceHashTransform.destroy(err));
    nodeStream.pipe(sourceHashTransform);

    await this.storage.upload(req.storagePath, sink);

    // A transfer that ends early produces a short object with a perfectly consistent
    // checksum of the bytes that did arrive, so without this a truncated 1.6 GB artifact
    // reaches `available` and is served. Compare against whatever size upstream committed
    // to before the body was read — and note the number describes the SOURCE bytes: it is
    // what upstream sent, not what the transform produced.
    const advertisedSize = advertisedSourceSize(req.expectedSize, response);
    if (advertisedSize !== undefined && advertisedSize !== sourceSize) {
      throw new Error(
        `Size mismatch: upstream advertised ${advertisedSize} bytes, received ${sourceSize}`,
      );
    }

    const sourceChecksum = sourceHash.digest("hex");

    const expectedChecksum =
      req.expectedChecksum ??
      (req.checksumUrl
        ? await fetchChecksumFromUrl(req.checksumUrl, this.checksumFetchImpl, algorithm)
        : undefined);

    // The upstream digest is verified against the source bytes, always. What is recorded on
    // the artifact is the digest of the stored bytes (WAL-57 AC3) — the same number as the
    // source when no transform ran, permanently different when one did.
    if (expectedChecksum && expectedChecksum !== sourceChecksum) {
      throw new Error(`Checksum mismatch: expected ${expectedChecksum}, got ${sourceChecksum}`);
    }

    let meta: TransformResultMeta | null = null;
    if (transformer && req.transform && transformMeta) {
      meta = await transformMeta;
      const problems = checkGate(meta, req.transform);
      if (problems.length > 0) {
        throw new Error(problems.join("; "));
      }
    }

    const actualChecksum = outputHash ? outputHash.digest("hex") : sourceChecksum;
    const actualFileSize = outputHash ? outputSize : sourceSize;

    if (dryRun) {
      return {
        status: "skipped",
        attempts: attempt,
        transformReport: {
          transform: transformer ? transformer.id : "(none)",
          entryCount: meta?.entryCount ?? 0,
          outputSize: actualFileSize,
          outputChecksum: actualChecksum,
          requirePathsPresent: meta?.pathsPresent ?? [],
          requirePathsMissing: meta?.pathsMissing ?? [],
          droppedSymlinks: meta?.droppedSymlinks ?? [],
        },
      };
    }

    await this.statusRepo.updateArtifactStatus(this.pool, req.artifactId, {
      status: "available",
      gcs_path: req.storagePath,
      file_size: actualFileSize,
      checksum: actualChecksum,
      checksum_type: algorithm,
      // Provenance (WAL-58): only a repackaged artifact carries the source side of the
      // split; an untransformed one keeps the pre-transform shape, NULLs and all.
      ...(transformer
        ? {
            source_checksum: sourceChecksum,
            source_file_size: sourceSize,
            transform: transformer.id,
          }
        : {}),
      error_message: null,
      download_completed_at: new Date(),
    });

    if (meta && meta.droppedSymlinks.length > 0) {
      // A drop is config-approved, but it must be visible where syncs are audited.
      log.info(
        { artifactId: req.artifactId, droppedSymlinks: meta.droppedSymlinks },
        "Transform dropped configured symlink entries",
      );
    }

    return {
      status: "available",
      attempts: attempt,
      storagePath: req.storagePath,
      fileSize: actualFileSize,
      checksum: actualChecksum,
      ...(transformer
        ? {
            sourceChecksum,
            sourceFileSize: sourceSize,
            transform: transformer.id,
          }
        : {}),
    };
  }
}

/**
 * The byte count this transfer is expected to deliver, where one can be trusted: the upstream
 * API's published size if the caller has one, otherwise the response's own `Content-Length`.
 *
 * Neither survives a content-coded response. `fetch` decodes the body before we count it, so
 * the header describes the encoded bytes; and an API-published size describes the file as the
 * publisher stores it, which a coding hop is under no obligation to round-trip. Comparing
 * either against the decoded count risks failing a transfer that arrived intact, so a
 * content-coded response skips the check whichever number the caller supplied — the guard is a
 * property of the response, not of where the number came from (WAL-73 finding 5).
 */
function advertisedSourceSize(
  expectedSize: number | undefined,
  response: Response,
): number | undefined {
  const encoding = response.headers.get("content-encoding");
  if (encoding && encoding.toLowerCase() !== "identity") return undefined;

  if (expectedSize !== undefined) return expectedSize;

  const header = response.headers.get("content-length");
  if (header === null) return undefined;

  const size = Number(header);
  return Number.isSafeInteger(size) && size >= 0 ? size : undefined;
}

/** Fetch a checksum sidecar file and extract the first digest-like token from its content. */
async function fetchChecksumFromUrl(
  url: string,
  fetchImpl: typeof fetch,
  algorithm: ChecksumAlgorithm,
): Promise<string> {
  const response = await fetchImpl(url);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} fetching checksum from ${url}`);
  }

  const text = await response.text();

  if (!text.trim()) {
    throw new Error(`Empty checksum file at ${url}`);
  }

  const digestLength = algorithm === "sha1" ? 40 : 64;
  const digestRegex = new RegExp(`[a-fA-F0-9]{${digestLength}}`);
  const match = text.match(digestRegex);

  if (!match) {
    throw new Error(`No ${algorithm} digest found in checksum file at ${url}`);
  }

  return match[0].toLowerCase();
}
