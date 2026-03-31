import crypto from "crypto";
import { Readable } from "stream";
import { describe, expect, it, vi } from "vitest";
import { Pool } from "pg";
import { DownloadService } from "../../src/services/download-service.js";
import { StorageBackend } from "../../src/storage/types.js";

async function drainStream(stream: Readable): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  for await (const _chunk of stream) { /* drain so hash transform fires */ }
}

function makeUploadMock() {
  return vi.fn().mockImplementation((_key: string, stream: Readable) => drainStream(stream));
}

function makeResponse(body: string, ok = true, status = 200): Response {
  return new Response(Buffer.from(body), { status, statusText: ok ? "OK" : "ERR" });
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
        for await (const _chunk of stream) { /* drain */ }
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
    const fetchImpl = vi.fn().mockResolvedValue(
      new Response(erroringBody, { status: 200 }),
    );

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
});
