import fs from "fs";
import path from "path";
import os from "os";
import { Readable } from "stream";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildArtifactPath } from "../../src/storage/types.js";
import { LocalStorageBackend } from "../../src/storage/local.js";

const ROOT = path.join(os.tmpdir(), "walrus-storage-test");

beforeAll(() => {
  fs.rmSync(ROOT, { recursive: true, force: true });
  fs.mkdirSync(ROOT, { recursive: true });
});

afterAll(() => {
  fs.rmSync(ROOT, { recursive: true, force: true });
});

describe("LocalStorageBackend", () => {
  it("uploads, checks exists, downloads, and deletes", async () => {
    const storage = new LocalStorageBackend(ROOT);
    const key = "uv/0.6.2/linux/x86-64/uv.tar.gz";
    await storage.upload(key, Readable.from(Buffer.from("hello-world")));
    expect(await storage.exists(key)).toBe(true);

    const downloaded = await storage.download(key);
    expect(downloaded.toString("utf8")).toBe("hello-world");

    await storage.delete(key);
    expect(await storage.exists(key)).toBe(false);
  });

  it("uses package/version/os/arch/filename path convention", () => {
    const artifactPath = buildArtifactPath({
      packageName: "golang",
      version: "1.24.1",
      os: "linux",
      arch: "x86-64",
      filename: "go1.24.1.linux-amd64.tar.gz",
    });

    expect(artifactPath).toBe("golang/1.24.1/linux/x86-64/go1.24.1.linux-amd64.tar.gz");
  });

  describe("ranged reads (WAL-66)", () => {
    const key = "ranged/1.0.0/linux/x86-64/blob.bin";
    const body = "0123456789";

    beforeAll(async () => {
      await new LocalStorageBackend(ROOT).upload(key, Readable.from(Buffer.from(body)));
    });

    async function read(range?: { start: number; end: number }): Promise<string> {
      const chunks: Buffer[] = [];
      for await (const chunk of new LocalStorageBackend(ROOT).stream(key, range)) {
        chunks.push(Buffer.from(chunk as Buffer));
      }
      return Buffer.concat(chunks).toString();
    }

    it("returns only the requested bytes", async () => {
      expect(await read({ start: 2, end: 5 })).toBe("2345");
    });

    it("includes both boundaries — end is the last byte, not one past it", async () => {
      expect(await read({ start: 0, end: 0 })).toBe("0");
      expect(await read({ start: 9, end: 9 })).toBe("9");
      expect(await read({ start: 0, end: 9 })).toBe(body);
    });

    it("returns the whole object when no range is given", async () => {
      expect(await read()).toBe(body);
    });
  });

  it("auto-creates missing directories on upload", async () => {
    const storage = new LocalStorageBackend(ROOT);
    const key = "nested/pkg/1.0.0/macos/arm64/bin.zip";

    await storage.upload(key, Readable.from(Buffer.from("x")));

    const fullPath = path.join(ROOT, key);
    expect(fs.existsSync(path.dirname(fullPath))).toBe(true);
    expect(fs.existsSync(fullPath)).toBe(true);
  });
});
