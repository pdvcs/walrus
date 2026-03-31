import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { Storage } from "@google-cloud/storage";
import { StorageBackend } from "./types.js";

export class GcsStorageBackend implements StorageBackend {
  private readonly storage = new Storage();

  constructor(private readonly bucketName: string) {}

  async upload(key: string, stream: Readable): Promise<void> {
    await pipeline(stream, this.storage.bucket(this.bucketName).file(key).createWriteStream());
  }

  async download(key: string): Promise<Buffer> {
    const [data] = await this.storage.bucket(this.bucketName).file(key).download();
    return data;
  }

  stream(key: string): Readable {
    return this.storage.bucket(this.bucketName).file(key).createReadStream();
  }

  async delete(key: string): Promise<void> {
    try {
      await this.storage.bucket(this.bucketName).file(key).delete();
    } catch (err) {
      const notFound =
        err instanceof Error && "code" in err && (err as { code?: number }).code === 404;
      if (!notFound) throw err;
    }
  }

  async exists(key: string): Promise<boolean> {
    const [exists] = await this.storage.bucket(this.bucketName).file(key).exists();
    return exists;
  }
}
