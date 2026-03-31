import crypto from "crypto";
import { Readable, Transform } from "stream";
import { Pool } from "pg";
import { updateArtifactStatus } from "../db/queries/artifacts.js";
import { ArtifactRow } from "../types/db.js";
import { StorageBackend } from "../storage/types.js";

export type ChecksumAlgorithm = "sha256" | "sha1";

export interface DownloadRequest {
  artifactId: number;
  upstreamUrl: string;
  storagePath: string;
  expectedChecksum?: string;
  checksumUrl?: string; // URL to fetch the expected checksum from (e.g. .sha256 sidecar)
  checksumType?: ChecksumAlgorithm;
}

export interface ArtifactStatusRepo {
  updateArtifactStatus: typeof updateArtifactStatus;
}

export interface DownloadServiceOptions {
  fetchImpl?: typeof fetch;
  maxRetries?: number;
  statusRepo?: ArtifactStatusRepo;
}

export interface DownloadResult {
  status: ArtifactRow["status"] | "skipped";
  attempts: number;
  storagePath?: string;
  fileSize?: number;
  checksum?: string;
  error?: string;
}

export class DownloadService {
  private readonly fetchImpl: typeof fetch;
  private readonly maxRetries: number;
  private readonly statusRepo: ArtifactStatusRepo;

  constructor(
    private readonly pool: Pool,
    private readonly storage: StorageBackend,
    opts: DownloadServiceOptions = {},
  ) {
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.maxRetries = opts.maxRetries ?? 2;
    this.statusRepo = opts.statusRepo ?? { updateArtifactStatus };
  }

  async downloadArtifact(req: DownloadRequest, dryRun = false): Promise<DownloadResult> {
    if (dryRun) {
      return { status: "skipped", attempts: 0 };
    }

    await this.statusRepo.updateArtifactStatus(this.pool, req.artifactId, {
      status: "downloading",
      download_started_at: new Date(),
      error_message: null,
    });

    const algorithm = req.checksumType ?? "sha256";
    const maxAttempts = this.maxRetries + 1;
    let lastError: Error | null = null;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      try {
        const response = await this.fetchImpl(req.upstreamUrl);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status} from ${req.upstreamUrl}`);
        }

        if (!response.body) {
          throw new Error(`Empty response body from ${req.upstreamUrl}`);
        }

        const hash = crypto.createHash(algorithm);
        let fileSize = 0;

        const hashTransform = new Transform({
          transform(chunk: Buffer, _enc, cb) {
            hash.update(chunk);
            fileSize += chunk.length;
            cb(null, chunk);
          },
        });

        const nodeStream = Readable.fromWeb(response.body);
        nodeStream.on("error", (err) => hashTransform.destroy(err));
        nodeStream.pipe(hashTransform);

        await this.storage.upload(req.storagePath, hashTransform);

        const actualChecksum = hash.digest("hex");

        const expectedChecksum =
          req.expectedChecksum ??
          (req.checksumUrl
            ? await fetchChecksumFromUrl(req.checksumUrl, this.fetchImpl, algorithm)
            : undefined);

        if (expectedChecksum && expectedChecksum !== actualChecksum) {
          await this.storage.delete(req.storagePath);
          throw new Error(`Checksum mismatch: expected ${expectedChecksum}, got ${actualChecksum}`);
        }

        await this.statusRepo.updateArtifactStatus(this.pool, req.artifactId, {
          status: "available",
          gcs_path: req.storagePath,
          file_size: fileSize,
          checksum: actualChecksum,
          checksum_type: algorithm,
          error_message: null,
          download_completed_at: new Date(),
        });

        return {
          status: "available",
          attempts: attempt,
          storagePath: req.storagePath,
          fileSize,
          checksum: actualChecksum,
        };
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < maxAttempts) {
          continue;
        }
      }
    }

    await this.statusRepo.updateArtifactStatus(this.pool, req.artifactId, {
      status: "failed",
      error_message: lastError?.message ?? "download failed",
      download_completed_at: new Date(),
    });

    return {
      status: "failed",
      attempts: maxAttempts,
      error: lastError?.message ?? "download failed",
    };
  }
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
