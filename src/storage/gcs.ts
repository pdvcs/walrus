import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { Storage } from "@google-cloud/storage";
import { ByteRange, StorageBackend } from "./types.js";

/**
 * The subset of `@google-cloud/storage` this backend uses. Declared structurally so a test can
 * supply a double without a bucket, credentials, or an emulator.
 */
export interface GcsFileLike {
  createWriteStream: (options: { chunkSize?: number }) => NodeJS.WritableStream;
  createReadStream: (options?: { start?: number; end?: number }) => NodeJS.ReadableStream;
  download: () => Promise<[Buffer]>;
  delete: () => Promise<unknown>;
  exists: () => Promise<[boolean]>;
}

export interface GcsClientLike {
  bucket: (name: string) => { file: (key: string) => GcsFileLike };
}

export interface GcsStorageOptions {
  /**
   * Resumable-upload chunk size in bytes. Its presence is the switch: with no `chunkSize` the
   * library streams into one PUT that cannot resume, so a blip at 1.5 GB of a 1.6 GB artifact
   * discards the whole transfer. See `GCS_UPLOAD_CHUNK_BYTES`.
   */
  chunkSize?: number;
  /** Injection seam for tests; production uses a real `Storage`. */
  client?: GcsClientLike;
}

export class GcsStorageBackend implements StorageBackend {
  private readonly storage: GcsClientLike;
  private readonly chunkSize: number | undefined;

  constructor(
    private readonly bucketName: string,
    options: GcsStorageOptions = {},
  ) {
    this.storage = options.client ?? (new Storage() as unknown as GcsClientLike);
    this.chunkSize = options.chunkSize;
  }

  private file(key: string): GcsFileLike {
    return this.storage.bucket(this.bucketName).file(key);
  }

  async upload(key: string, stream: Readable): Promise<void> {
    await pipeline(stream, this.file(key).createWriteStream({ chunkSize: this.chunkSize }));
  }

  async download(key: string): Promise<Buffer> {
    const [data] = await this.file(key).download();
    return data;
  }

  stream(key: string, range?: ByteRange): Readable {
    // `start`/`end` are passed to GCS itself as a Range header, so only the requested bytes are
    // fetched — reading the whole object and discarding a prefix would defeat the point.
    const readable = range
      ? this.file(key).createReadStream({ start: range.start, end: range.end })
      : this.file(key).createReadStream();
    return readable as Readable;
  }

  async delete(key: string): Promise<void> {
    try {
      await this.file(key).delete();
    } catch (err) {
      const notFound =
        err instanceof Error && "code" in err && (err as { code?: number }).code === 404;
      if (!notFound) throw err;
    }
  }

  async exists(key: string): Promise<boolean> {
    const [exists] = await this.file(key).exists();
    return exists;
  }
}
