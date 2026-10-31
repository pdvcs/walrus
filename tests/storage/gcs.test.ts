import { Readable, Writable } from "stream";
import { describe, expect, it, vi } from "vitest";
import { GcsStorageBackend, GcsClientLike, GcsFileLike } from "../../src/storage/gcs.js";

/**
 * A double for the one file the backend touches. Real GCS needs credentials, a bucket, and a
 * network; what these tests are about is the options walrus passes, which is exactly what the
 * double can observe.
 */
function makeClient() {
  const writes: Buffer[] = [];
  const file: GcsFileLike = {
    createWriteStream: vi.fn().mockImplementation(
      () =>
        new Writable({
          write(chunk: Buffer, _enc, cb) {
            writes.push(Buffer.from(chunk));
            cb();
          },
        }),
    ),
    createReadStream: vi.fn().mockReturnValue(Readable.from(Buffer.from("range-bytes"))),
    download: vi.fn().mockResolvedValue([Buffer.from("whole")]),
    delete: vi.fn().mockResolvedValue(undefined),
    exists: vi.fn().mockResolvedValue([true]),
  };
  const client: GcsClientLike = { bucket: vi.fn().mockReturnValue({ file: () => file }) };
  return { client, file, writes };
}

describe("GcsStorageBackend", () => {
  it("uploads with the configured resumable chunk size", async () => {
    // chunkSize being set at all is what puts the client in multi-chunk resumable mode; unset,
    // a 1.6 GB upload is one PUT that restarts from zero on any blip (WAL-67).
    const { client, file, writes } = makeClient();
    const storage = new GcsStorageBackend("bucket", { client, chunkSize: 8 * 1024 * 1024 });

    await storage.upload("pkg/1.0.0/linux/x86-64/f.tar.gz", Readable.from(Buffer.from("data")));

    expect(file.createWriteStream).toHaveBeenCalledWith({ chunkSize: 8 * 1024 * 1024 });
    expect(Buffer.concat(writes).toString()).toBe("data");
  });

  it("passes a byte range to GCS rather than reading the whole object", async () => {
    const { client, file } = makeClient();
    const storage = new GcsStorageBackend("bucket", { client });

    storage.stream("k", { start: 100, end: 199 });

    expect(file.createReadStream).toHaveBeenCalledWith({ start: 100, end: 199 });
  });

  it("reads the whole object when no range is given", () => {
    const { client, file } = makeClient();
    const storage = new GcsStorageBackend("bucket", { client });

    storage.stream("k");

    expect(file.createReadStream).toHaveBeenCalledWith();
  });

  it("treats a missing object as already deleted", async () => {
    const { client, file } = makeClient();
    (file.delete as ReturnType<typeof vi.fn>).mockRejectedValue(
      Object.assign(new Error("No such object"), { code: 404 }),
    );
    const storage = new GcsStorageBackend("bucket", { client });

    await expect(storage.delete("k")).resolves.toBeUndefined();
  });
});
