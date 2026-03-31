import path from "path";
import fs from "fs/promises";
import { existsSync, createWriteStream, createReadStream } from "fs";
import { pipeline } from "stream/promises";
import { Readable } from "stream";
import { StorageBackend } from "./types.js";

export class LocalStorageBackend implements StorageBackend {
  constructor(private readonly rootDir: string) {}

  private resolve(key: string): string {
    return path.join(this.rootDir, key);
  }

  async upload(key: string, stream: Readable): Promise<void> {
    const targetPath = this.resolve(key);
    const dir = path.dirname(targetPath);
    await fs.mkdir(dir, { recursive: true });
    await pipeline(stream, createWriteStream(targetPath));
  }

  async download(key: string): Promise<Buffer> {
    return fs.readFile(this.resolve(key));
  }

  stream(key: string): Readable {
    return createReadStream(this.resolve(key));
  }

  async delete(key: string): Promise<void> {
    try {
      await fs.unlink(this.resolve(key));
    } catch (err) {
      const isMissing =
        err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT";
      if (!isMissing) throw err;
    }
  }

  exists(key: string): Promise<boolean> {
    return Promise.resolve(existsSync(this.resolve(key)));
  }
}
