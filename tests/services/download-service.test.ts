import crypto from "crypto";
import fs from "fs";
import path from "path";
import { Readable } from "stream";
import { describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { DownloadService } from "../../src/services/download-service.js";
import { StorageBackend } from "../../src/storage/types.js";
import { Semaphore } from "../../src/common/semaphore.js";

const FIXTURES = path.join(process.cwd(), "tests/fixtures");

function readFixture(name: string): Buffer {
  return fs.readFileSync(path.join(FIXTURES, name));
}

async function drainStream(stream: Readable): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for await (const _chunk of stream) {
    /* drain so hash transform fires */
  }
}

function makeUploadMock() {
  return vi.fn().mockImplementation((_key: string, stream: Readable) => drainStream(stream));
}

function makeResponse(body: string, ok = true, status = 200): Response {
  return new Response(Buffer.from(body), { status, statusText: ok ? "OK" : "ERR" });
}

/** A response that advertises a size, the way a real upstream does. */
function makeSizedResponse(body: string, advertised: number, headers: HeadersInit = {}): Response {
  return new Response(Buffer.from(body), {
    status: 200,
    headers: { "content-length": String(advertised), ...headers },
  });
}

/** A binary-safe response: the bytes go over exactly as given (no string re-encoding). */
function makeBinaryResponse(body: Buffer, headers: HeadersInit = {}): Response {
  return new Response(new Uint8Array(body), { status: 200, headers });
}

describe("DownloadService", () => {
  it("downloads, verifies checksum, uploads, and marks available", async () => {
    const storage: StorageBackend = {
      upload: makeUploadMock(),
      download: vi.fn(),
      delete: vi.fn(),
      exists: vi.fn(),
    };

    const statusRepo = {
      updateArtifactStatus: vi.fn().mockResolvedValue(null),
    };

    const body = "binary-data";
    const expected = crypto.createHash("sha256").update(body).digest("hex");
    const fetchImpl = vi.fn().mockResolvedValue(makeResponse(body));

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
      maxRetries: 1,
    });

    const result = await service.downloadArtifact({
      artifactId: 42,
      upstreamUrl: "https://example.test/file",
      storagePath: "uv/0.6.2/linux/x86-64/uv.tar.gz",
      expectedChecksum: expected,
      checksumType: "sha256",
    });

    expect(result.status).toBe("available");
    expect(result.attempts).toBe(1);
    expect(vi.mocked(storage.upload)).toHaveBeenCalledOnce();
    expect(statusRepo.updateArtifactStatus).toHaveBeenCalledTimes(2);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("marks failed when checksum does not match", async () => {
    const storage: StorageBackend = {
      upload: makeUploadMock(),
      download: vi.fn(),
      delete: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn(),
    };

    const statusRepo = {
      updateArtifactStatus: vi.fn().mockResolvedValue(null),
    };

    const fetchImpl = vi.fn().mockResolvedValue(makeResponse("bad-data"));

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
      maxRetries: 0,
    });

    const result = await service.downloadArtifact({
      artifactId: 7,
      upstreamUrl: "https://example.test/file",
      storagePath: "golang/1.24.1/linux/x86-64/go.tar.gz",
      expectedChecksum: "deadbeef",
      checksumType: "sha256",
    });

    expect(result.status).toBe("failed");
    expect(vi.mocked(storage.upload)).toHaveBeenCalledOnce();
    expect(vi.mocked(storage.delete)).toHaveBeenCalledOnce();
    expect(statusRepo.updateArtifactStatus).toHaveBeenCalledTimes(2);
  });

  it("fetches checksum from checksumUrl when expectedChecksum is absent", async () => {
    const storage: StorageBackend = {
      upload: makeUploadMock(),
      download: vi.fn(),
      delete: vi.fn(),
      exists: vi.fn(),
    };

    const statusRepo = {
      updateArtifactStatus: vi.fn().mockResolvedValue(null),
    };

    const body = "binary-data";
    const expected = crypto.createHash("sha256").update(body).digest("hex");
    // Sidecar .sha256 file — includes filename after the hash, like sha256sum output
    const checksumFileContent = `${expected}  uv-x86_64-unknown-linux-gnu.tar.gz\n`;

    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(makeResponse(body)) // artifact
      .mockResolvedValueOnce(makeResponse(checksumFileContent)); // checksum sidecar

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
      maxRetries: 0,
    });

    const result = await service.downloadArtifact({
      artifactId: 55,
      upstreamUrl: "https://example.test/uv.tar.gz",
      storagePath: "uv/0.10.7/linux/x86-64/uv.tar.gz",
      checksumUrl: "https://example.test/uv.tar.gz.sha256",
      checksumType: "sha256",
    });

    expect(result.status).toBe("available");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(fetchImpl).toHaveBeenNthCalledWith(2, "https://example.test/uv.tar.gz.sha256");
    expect(vi.mocked(storage.upload)).toHaveBeenCalledOnce();
  });

  it("accepts checksum sidecar content in non-sha256sum format", async () => {
    const storage: StorageBackend = {
      upload: makeUploadMock(),
      download: vi.fn(),
      delete: vi.fn(),
      exists: vi.fn(),
    };

    const statusRepo = {
      updateArtifactStatus: vi.fn().mockResolvedValue(null),
    };

    const body = "windows-binary";
    const expected = crypto.createHash("sha256").update(body).digest("hex").toUpperCase();
    const checksumFileContent = `SHA256 (ripgrep-15.1.0-x86_64-pc-windows-msvc.zip) = ${expected}\n`;

    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(makeResponse(body)) // artifact
      .mockResolvedValueOnce(makeResponse(checksumFileContent)); // checksum sidecar

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
      maxRetries: 0,
    });

    const result = await service.downloadArtifact({
      artifactId: 56,
      upstreamUrl: "https://example.test/ripgrep.zip",
      storagePath: "ripgrep/15.1.0/windows/x86-64/ripgrep.zip",
      checksumUrl: "https://example.test/ripgrep.zip.sha256",
      checksumType: "sha256",
    });

    expect(result.status).toBe("available");
    expect(vi.mocked(storage.upload)).toHaveBeenCalledOnce();
  });

  it("retries failed fetches until success", async () => {
    const storage: StorageBackend = {
      upload: makeUploadMock(),
      download: vi.fn(),
      delete: vi.fn(),
      exists: vi.fn(),
    };

    const statusRepo = {
      updateArtifactStatus: vi.fn().mockResolvedValue(null),
    };

    const fetchImpl = vi
      .fn()
      .mockRejectedValueOnce(new Error("network"))
      .mockRejectedValueOnce(new Error("still bad"))
      .mockResolvedValue(makeResponse("ok"));

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
      maxRetries: 2,
    });

    const result = await service.downloadArtifact({
      artifactId: 99,
      upstreamUrl: "https://example.test/file",
      storagePath: "x/y/z",
    });

    expect(result.status).toBe("available");
    expect(result.attempts).toBe(3);
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("streams the exact response bytes to storage without buffering", async () => {
    const body = "streaming-content";
    let uploadedBytes = Buffer.alloc(0);

    const storage: StorageBackend = {
      upload: vi.fn().mockImplementation(async (_key: string, stream: Readable) => {
        const chunks: Buffer[] = [];
        for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
        uploadedBytes = Buffer.concat(chunks);
      }),
      download: vi.fn(),
      delete: vi.fn(),
      exists: vi.fn(),
    };

    const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
    const fetchImpl = vi.fn().mockResolvedValue(makeResponse(body));

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
    });

    await service.downloadArtifact({
      artifactId: 1,
      upstreamUrl: "https://example.test/file",
      storagePath: "pkg/1.0/linux/x86-64/file.tar.gz",
    });

    expect(uploadedBytes.toString("utf8")).toBe(body);
  });

  it("marks failed and does not leave orphan in storage when response stream errors", async () => {
    const storage: StorageBackend = {
      upload: vi.fn().mockImplementation(async (_key: string, stream: Readable) => {
        // Consume a bit then error
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        for await (const _chunk of stream) {
          /* drain */
        }
      }),
      download: vi.fn(),
      delete: vi.fn().mockResolvedValue(undefined),
      exists: vi.fn(),
    };

    const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };

    // Simulate a response whose body stream errors mid-read
    const erroringBody = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("partial"));
        controller.error(new Error("network reset"));
      },
    });
    const fetchImpl = vi.fn().mockResolvedValue(new Response(erroringBody, { status: 200 }));

    const service = new DownloadService({} as Pool, storage, {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      statusRepo,
      maxRetries: 0,
    });

    const result = await service.downloadArtifact({
      artifactId: 2,
      upstreamUrl: "https://example.test/file",
      storagePath: "pkg/1.0/linux/x86-64/file.tar.gz",
    });

    expect(result.status).toBe("failed");
    expect(result.error).toMatch(/network reset/);
  });

  describe("size verification (WAL-67)", () => {
    function harness() {
      const storage: StorageBackend = {
        upload: makeUploadMock(),
        download: vi.fn(),
        delete: vi.fn().mockResolvedValue(undefined),
        exists: vi.fn(),
      };
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      return { storage, statusRepo };
    }

    it("fails a truncated transfer rather than marking it available", async () => {
      // The bytes that did arrive hash perfectly well, so the checksum alone cannot catch this
      // unless upstream published a digest — which is exactly when truncation goes unnoticed.
      const { storage, statusRepo } = harness();
      const fetchImpl = vi.fn().mockResolvedValue(makeSizedResponse("short", 5_000_000));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 1,
        upstreamUrl: "https://example.test/big.zip",
        storagePath: "p/1/os/arch/big.zip",
      });

      expect(result.status).toBe("failed");
      expect(result.error).toMatch(/advertised 5000000 bytes, received 5/);
      expect(storage.delete).toHaveBeenCalledWith("p/1/os/arch/big.zip");
      const statuses = statusRepo.updateArtifactStatus.mock.calls.map((c) => c[2].status);
      expect(statuses).not.toContain("available");
    });

    it("prefers the size the upstream API published over the response header", async () => {
      const { storage, statusRepo } = harness();
      // Header agrees with the body; the API's own number does not, and wins.
      const fetchImpl = vi.fn().mockResolvedValue(makeSizedResponse("twelve bytes", 12));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 2,
        upstreamUrl: "https://example.test/f",
        storagePath: "p/2/os/arch/f",
        expectedSize: 999,
      });

      expect(result.status).toBe("failed");
      expect(result.error).toMatch(/advertised 999 bytes, received 12/);
    });

    it("accepts a transfer whose length matches", async () => {
      const { storage, statusRepo } = harness();
      const body = "exactly-this";
      const fetchImpl = vi.fn().mockResolvedValue(makeSizedResponse(body, body.length));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
      });

      const result = await service.downloadArtifact({
        artifactId: 3,
        upstreamUrl: "https://example.test/f",
        storagePath: "p/3/os/arch/f",
        expectedSize: body.length,
      });

      expect(result.status).toBe("available");
      expect(result.fileSize).toBe(body.length);
      expect(storage.delete).not.toHaveBeenCalled();
    });

    it("does not compare against Content-Length on a content-coded response", async () => {
      // fetch decodes the body before we count it, so the header describes the compressed
      // bytes; comparing the two would fail every gzipped transfer.
      const { storage, statusRepo } = harness();
      const fetchImpl = vi
        .fn()
        .mockResolvedValue(makeSizedResponse("decoded-body", 4, { "content-encoding": "gzip" }));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
      });

      const result = await service.downloadArtifact({
        artifactId: 4,
        upstreamUrl: "https://example.test/f",
        storagePath: "p/4/os/arch/f",
      });

      expect(result.status).toBe("available");
    });

    it("makes two whole-transfer attempts by default, not three", async () => {
      // An attempt can be 1.6 GB now, and the GCS half retries its own chunks, so the outer
      // loop only re-covers the upstream fetch. The next scheduled sync is the third attempt.
      const { storage, statusRepo } = harness();
      const fetchImpl = vi.fn().mockRejectedValue(new Error("network"));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
      });

      const result = await service.downloadArtifact({
        artifactId: 5,
        upstreamUrl: "https://example.test/f",
        storagePath: "p/5/os/arch/f",
      });

      expect(result.status).toBe("failed");
      expect(fetchImpl).toHaveBeenCalledTimes(2);
    });
  });

  describe("transform wiring (WAL-57)", () => {
    const BASIC_FIXTURE = readFixture("transform-basic.tar.bz2");
    const SOURCE_DIGEST = crypto.createHash("sha256").update(BASIC_FIXTURE).digest("hex");

    const TRANSFORM = {
      type: "tar-bz2-to-zip" as const,
      extension: "zip",
      require_paths: ["cmd/git.exe", "usr/bin/bash.exe"],
    };

    function capturingStorage() {
      let uploadedBytes = Buffer.alloc(0);
      const storage: StorageBackend = {
        upload: vi.fn().mockImplementation(async (_key: string, stream: Readable) => {
          const chunks: Buffer[] = [];
          for await (const chunk of stream) chunks.push(Buffer.from(chunk as Uint8Array));
          uploadedBytes = Buffer.concat(chunks);
        }),
        download: vi.fn(),
        delete: vi.fn().mockResolvedValue(undefined),
        exists: vi.fn(),
      };
      return {
        storage,
        get uploadedBytes(): Buffer {
          return uploadedBytes;
        },
      };
    }

    it("a platform without a transform block behaves exactly as before", async () => {
      const { storage } = capturingStorage();
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const body = "plain-bytes";
      const fetchImpl = vi.fn().mockResolvedValue(makeResponse(body));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 10,
        upstreamUrl: "https://example.test/file",
        storagePath: "p/1/linux/x86-64/file.tar.gz",
      });

      expect(result.status).toBe("available");
      expect(result.transform).toBeUndefined();
      expect(result.sourceChecksum).toBeUndefined();
      const availableCall = statusRepo.updateArtifactStatus.mock.calls.find(
        (c) => c[2].status === "available",
      );
      expect(availableCall![2].source_checksum).toBeUndefined();
      expect(availableCall![2].transform).toBeUndefined();
      expect(availableCall![2].checksum).toBe(
        crypto.createHash("sha256").update(body).digest("hex"),
      );
    });

    it("runs the transform: source digest is verified, stored bytes are the zip", async () => {
      const capture = capturingStorage();
      const { storage } = capture;
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const fetchImpl = vi
        .fn()
        .mockResolvedValue(
          makeBinaryResponse(BASIC_FIXTURE, { "content-length": String(BASIC_FIXTURE.length) }),
        );

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 11,
        upstreamUrl: "https://example.test/Git-2.55.0.5-64-bit.tar.bz2",
        storagePath: "gitwindows/2.55.0.5/windows/x86-64/Git-2.55.0.5-windows-x86-64.zip",
        expectedChecksum: SOURCE_DIGEST, // upstream's digest describes the tar.bz2
        checksumType: "sha256",
        transform: {
          ...TRANSFORM,
          filename_template: "Git-{version}-{os}-{arch}.zip",
          min_entries: 3,
        },
      });

      expect(result.status).toBe("available");
      // The upstream digest was verified against the SOURCE bytes (a mismatch would have failed).
      expect(result.sourceChecksum).toBe(SOURCE_DIGEST);
      expect(result.sourceFileSize).toBe(BASIC_FIXTURE.length);
      expect(result.transform).toBe("tar-bz2-to-zip@1");
      // What was stored — and recorded as `checksum` — is the transformed output.
      expect(capture.uploadedBytes.length).toBeGreaterThan(0);
      expect(capture.uploadedBytes.length).not.toBe(BASIC_FIXTURE.length);
      expect(result.checksum).toBe(
        crypto.createHash("sha256").update(capture.uploadedBytes).digest("hex"),
      );
      const availableCall = statusRepo.updateArtifactStatus.mock.calls.find(
        (c) => c[2].status === "available",
      );
      expect(availableCall![2].checksum).toBe(result.checksum);
      expect(availableCall![2].file_size).toBe(result.fileSize);
      expect(availableCall![2].source_checksum).toBe(SOURCE_DIGEST);
      expect(availableCall![2].source_file_size).toBe(BASIC_FIXTURE.length);
      expect(availableCall![2].transform).toBe("tar-bz2-to-zip@1");
    });

    it("a require_paths gate failure marks the artifact failed and deletes, naming the miss", async () => {
      const capture = capturingStorage();
      const { storage } = capture;
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const fetchImpl = vi.fn().mockResolvedValue(makeBinaryResponse(BASIC_FIXTURE));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 12,
        upstreamUrl: "https://example.test/tree.tar.bz2",
        storagePath: "p/1/windows/x86-64/tree.zip",
        transform: { ...TRANSFORM, require_paths: ["cmd/git.exe", "usr/bin/no-such.exe"] },
      });

      expect(result.status).toBe("failed");
      expect(result.error).toMatch(/missing required path\(s\): usr\/bin\/no-such\.exe/);
      expect(storage.delete).toHaveBeenCalledWith("p/1/windows/x86-64/tree.zip");
      const statuses = statusRepo.updateArtifactStatus.mock.calls.map((c) => c[2].status);
      expect(statuses).not.toContain("available");
      // The bytes made it as far as the sink but are recorded nowhere servable.
      expect(capture.uploadedBytes.length).toBeGreaterThan(0);
    });

    it("a min_entries gate failure fails the artifact", async () => {
      const { storage } = capturingStorage();
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const fetchImpl = vi.fn().mockResolvedValue(makeBinaryResponse(BASIC_FIXTURE));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 13,
        upstreamUrl: "https://example.test/tree.tar.bz2",
        storagePath: "p/1/windows/x86-64/tree.zip",
        transform: { ...TRANSFORM, min_entries: 9999 },
      });

      expect(result.status).toBe("failed");
      expect(result.error).toMatch(/below the required minimum of 9999/);
      expect(storage.delete).toHaveBeenCalled();
    });

    it("a mid-stream transform error (unsupported entry) fails and deletes", async () => {
      const { storage } = capturingStorage();
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const symlink = readFixture("transform-symlink.tar.bz2");
      const fetchImpl = vi.fn().mockResolvedValue(makeBinaryResponse(symlink));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact({
        artifactId: 14,
        upstreamUrl: "https://example.test/tree.tar.bz2",
        storagePath: "p/1/windows/x86-64/tree.zip",
        transform: TRANSFORM,
      });

      expect(result.status).toBe("failed");
      expect(result.error).toMatch(/unsupported tar entry type 'symlink/);
      expect(result.error).toMatch(/not listed in drop_symlinks/);
      expect(storage.delete).toHaveBeenCalledWith("p/1/windows/x86-64/tree.zip");
      expect(statusRepo.updateArtifactStatus).toHaveBeenCalledTimes(2); // downloading, failed
    });

    it("deletes unconditionally on a terminal failure, not only on a mismatch (AC8)", async () => {
      const { storage } = capturingStorage();
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      // Attempt 1 uploads something and then the response dies mid-stream; attempt 2 fails
      // on the fetch. Either way, no partial object may survive.
      let served = false;
      const erroringBody = () =>
        new ReadableStream({
          start(controller) {
            if (!served) {
              served = true;
              controller.enqueue(new TextEncoder().encode("partial"));
              controller.error(new Error("network reset"));
            } else {
              controller.error(new Error("still broken"));
            }
          },
        });
      const fetchImpl = vi
        .fn()
        .mockResolvedValueOnce(new Response(erroringBody(), { status: 200 }))
        .mockResolvedValue(new Response(erroringBody(), { status: 200 }));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
      });

      const result = await service.downloadArtifact({
        artifactId: 15,
        upstreamUrl: "https://example.test/f",
        storagePath: "p/1/os/arch/f",
      });

      expect(result.status).toBe("failed");
      expect(storage.delete).toHaveBeenCalledWith("p/1/os/arch/f");
    });

    it("dry-run with a transform runs the whole pipeline and reports; nothing is written", async () => {
      const capture = capturingStorage();
      const { storage } = capture;
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const fetchImpl = vi.fn().mockResolvedValue(makeBinaryResponse(BASIC_FIXTURE));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact(
        {
          artifactId: 16,
          upstreamUrl: "https://example.test/tree.tar.bz2",
          storagePath: "gitwindows/2.55.0.5/windows/x86-64/tree.zip",
          expectedChecksum: SOURCE_DIGEST,
          checksumType: "sha256",
          transform: TRANSFORM,
        },
        true,
      );

      expect(result.status).toBe("skipped");
      expect(statusRepo.updateArtifactStatus).not.toHaveBeenCalled();
      // The injected no-op storage drained the sink — the pipeline ran for real.
      expect(capture.uploadedBytes.length).toBeGreaterThan(0);
      expect(result.transformReport).toMatchObject({
        transform: "tar-bz2-to-zip@1",
        entryCount: 3,
        requirePathsPresent: ["cmd/git.exe", "usr/bin/bash.exe"],
        requirePathsMissing: [],
      });
      expect(result.transformReport!.outputSize).toBeGreaterThan(0);
      expect(result.transformReport!.outputChecksum).toBe(
        crypto.createHash("sha256").update(capture.uploadedBytes).digest("hex"),
      );
    });

    it("a gate failure in dry-run reports failure (validate exits non-zero)", async () => {
      const { storage } = capturingStorage();
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const fetchImpl = vi.fn().mockResolvedValue(makeBinaryResponse(BASIC_FIXTURE));

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
        maxRetries: 0,
      });

      const result = await service.downloadArtifact(
        {
          artifactId: 17,
          upstreamUrl: "https://example.test/tree.tar.bz2",
          storagePath: "p/1/windows/x86-64/tree.zip",
          transform: { ...TRANSFORM, require_paths: ["nope/missing.exe"] },
        },
        true,
      );

      expect(result.status).toBe("failed");
      expect(result.error).toMatch(/nope\/missing\.exe/);
    });

    it("dry-run without a transform skips entirely, as before", async () => {
      const { storage } = capturingStorage();
      const statusRepo = { updateArtifactStatus: vi.fn().mockResolvedValue(null) };
      const fetchImpl = vi.fn();

      const service = new DownloadService({} as Pool, storage, {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        statusRepo,
      });

      const result = await service.downloadArtifact(
        {
          artifactId: 18,
          upstreamUrl: "https://example.test/file",
          storagePath: "p/1/os/arch/f",
        },
        true,
      );

      expect(result).toEqual({ status: "skipped", attempts: 0 });
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(storage.upload).not.toHaveBeenCalled();
    });

    it("transforms are bounded independently of how many downloads run (WAL-61 AC2)", async () => {
      let concurrent = 0;
      let maxConcurrent = 0;
      const makeStorage = (): StorageBackend => ({
        upload: vi.fn().mockImplementation(async (_key: string, stream: Readable) => {
          concurrent += 1;
          maxConcurrent = Math.max(maxConcurrent, concurrent);
          await new Promise((resolve) => setTimeout(resolve, 20));
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          for await (const _chunk of stream) {
            /* drain */
          }
          concurrent -= 1;
        }),
        download: vi.fn(),
        delete: vi.fn().mockResolvedValue(undefined),
        exists: vi.fn(),
      });

      const semaphore = new Semaphore(1);
      const services = [0, 1].map(
        () =>
          new DownloadService({} as Pool, makeStorage(), {
            fetchImpl: vi
              .fn()
              .mockResolvedValue(makeBinaryResponse(readFixture("transform-hardlink.tar.bz2"))),
            statusRepo: { updateArtifactStatus: vi.fn().mockResolvedValue(null) },
            maxRetries: 0,
            transformSemaphore: semaphore,
          }),
      );

      const results = await Promise.all(
        services.map((service, i) =>
          service.downloadArtifact({
            artifactId: 20 + i,
            upstreamUrl: "https://example.test/tree.tar.bz2",
            storagePath: `p/${i}/windows/x86-64/tree.zip`,
            transform: {
              type: "tar-bz2-to-zip",
              extension: "zip",
              require_paths: [],
            },
          }),
        ),
      );

      expect(results.map((r) => r.status)).toEqual(["available", "available"]);
      expect(maxConcurrent).toBe(1);
    });
  });
});
