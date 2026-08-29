import { execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { PassThrough, Transform } from "stream";
import * as tar from "tar-stream";
import { describe, expect, it } from "vitest";
import {
  TarBz2ToZipTransform,
  UnsupportedEntryTypeError,
  UnresolvableHardlinkError,
  TAR_BZ2_TO_ZIP_ID,
} from "../../src/transform/tar-bz2-to-zip.js";
import { checkGate, getTransform, renderServedFilename } from "../../src/transform/index.js";
import { TransformConfig } from "../../src/types/package-config.js";

const FIXTURES = path.join(process.cwd(), "tests/fixtures");

const BASIC_CONFIG: TransformConfig = {
  type: "tar-bz2-to-zip",
  extension: "zip",
  require_paths: ["cmd/git.exe", "usr/bin/bash.exe"],
};

async function transformFixture(
  fixture: string,
  config: TransformConfig,
): Promise<{ bytes: Buffer; meta: Awaited<ReturnType<TarBz2ToZipTransform["apply"]>["meta"]> }> {
  const transform = new TarBz2ToZipTransform();
  const { output, meta } = transform.apply(fs.createReadStream(fixture), config);
  const chunks: Buffer[] = [];
  for await (const chunk of output) chunks.push(chunk as Buffer);
  return { bytes: Buffer.concat(chunks), meta: await meta };
}

/** Extract with the system unzip and return every file's content keyed by path. */
function readZipEntries(bytes: Buffer): Map<string, Buffer> {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-zip-"));
  try {
    const zipPath = path.join(tmp, "out.zip");
    fs.writeFileSync(zipPath, bytes);
    execSync(`unzip -q out.zip`, { cwd: tmp });
    const entries = new Map<string, Buffer>();
    const walk = (dir: string, prefix: string): void => {
      for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
        if (item.name === "out.zip") continue;
        const full = path.join(dir, item.name);
        const rel = prefix ? `${prefix}/${item.name}` : item.name;
        if (item.isDirectory()) walk(full, rel);
        else entries.set(rel, fs.readFileSync(full));
      }
    };
    walk(tmp, "");
    return entries;
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

/**
 * Peak of `external + arrayBuffers`, sampled on a timer. Buffers are allocated off the V8
 * heap, so `heapUsed` cannot see the archive content this transform is asserted not to
 * retain — 200 MiB of live Buffers moves heapUsed by roughly nothing. Sampling on a timer
 * rather than reading once at the end also catches a transient peak that has been released
 * by the time the pipeline settles.
 */
class BufferMemorySampler {
  private readonly base: number;
  private peak = 0;
  private readonly timer: NodeJS.Timeout;

  constructor(intervalMs = 20) {
    this.base = BufferMemorySampler.current();
    this.timer = setInterval(() => {
      this.peak = Math.max(this.peak, BufferMemorySampler.current() - this.base);
    }, intervalMs);
    this.timer.unref();
  }

  private static current(): number {
    const usage = process.memoryUsage();
    return usage.external + usage.arrayBuffers;
  }

  /** Final sample, stop, and report. */
  peakBytes(): number {
    this.peak = Math.max(this.peak, BufferMemorySampler.current() - this.base);
    clearInterval(this.timer);
    return this.peak;
  }
}

describe("tar-bz2-to-zip transform", () => {
  it("round-trips a fixture: entry set, content, and determinism", async () => {
    const first = await transformFixture(`${FIXTURES}/transform-basic.tar.bz2`, BASIC_CONFIG);
    expect(first.meta.entryCount).toBe(3);
    expect(first.meta.pathsPresent).toEqual(["cmd/git.exe", "usr/bin/bash.exe"]);
    expect(first.meta.pathsMissing).toEqual([]);

    const entries = readZipEntries(first.bytes);
    expect([...entries.keys()].sort()).toEqual(["cmd/git.exe", "etc/profile", "usr/bin/bash.exe"]);
    expect(entries.get("cmd/git.exe")!.toString()).toBe("git-binary-content\n");
    expect(entries.get("usr/bin/bash.exe")!.toString()).toBe("bash-content\n");
    expect(entries.get("etc/profile")!.toString()).toBe("profile\n");

    const second = await transformFixture(`${FIXTURES}/transform-basic.tar.bz2`, BASIC_CONFIG);
    expect(Buffer.compare(first.bytes, second.bytes)).toBe(0);
  });

  it("resolves hardlinks by duplicating the target's content", async () => {
    const { bytes, meta } = await transformFixture(`${FIXTURES}/transform-hardlink.tar.bz2`, {
      type: "tar-bz2-to-zip",
      extension: "zip",
      require_paths: ["bin/tool-link.exe"],
    });
    expect(meta.entryCount).toBe(2);
    const entries = readZipEntries(bytes);
    // A zip has no hardlink concept; the duplicate must carry the same bytes.
    expect(entries.get("bin/tool.exe")!.equals(entries.get("bin/tool-link.exe")!)).toBe(true);
    expect(entries.get("bin/tool-link.exe")!.toString()).toBe("tool-binary-content\n");

    // Hardlink duplicates go through yazl's read-stream path for backpressure, which means
    // the data-descriptor encoding every other entry already uses. Determinism has to hold
    // for that path too, not just for the plain-file fixture above.
    const second = await transformFixture(`${FIXTURES}/transform-hardlink.tar.bz2`, {
      type: "tar-bz2-to-zip",
      extension: "zip",
      require_paths: ["bin/tool-link.exe"],
    });
    expect(Buffer.compare(bytes, second.bytes)).toBe(0);
  });

  it("hard-fails on a symlink entry, naming the entry", async () => {
    await expect(
      transformFixture(`${FIXTURES}/transform-symlink.tar.bz2`, {
        type: "tar-bz2-to-zip",
        extension: "zip",
        require_paths: [],
      }),
    ).rejects.toBeInstanceOf(UnsupportedEntryTypeError);
  });

  it("hard-fails on a fifo entry", async () => {
    await expect(
      transformFixture(`${FIXTURES}/transform-fifo.tar.bz2`, {
        type: "tar-bz2-to-zip",
        extension: "zip",
        require_paths: [],
      }),
    ).rejects.toBeInstanceOf(UnsupportedEntryTypeError);
  });

  it("hard-fails on a hardlink whose target has not streamed past", async () => {
    await expect(
      transformFixture(`${FIXTURES}/transform-forward-hardlink.tar.bz2`, {
        type: "tar-bz2-to-zip",
        extension: "zip",
        require_paths: [],
      }),
    ).rejects.toBeInstanceOf(UnresolvableHardlinkError);
  });

  it("fails a hardlink whose target fell out of a too-small link cache", async () => {
    await expect(
      transformFixture(`${FIXTURES}/transform-hardlink.tar.bz2`, {
        type: "tar-bz2-to-zip",
        extension: "zip",
        require_paths: [],
        link_cache_bytes: 10, // the target is 20 bytes
      }),
    ).rejects.toBeInstanceOf(UnresolvableHardlinkError);
  });

  it("resolves hardlinks when the link cache is sized for the measured distance", async () => {
    const { meta } = await transformFixture(`${FIXTURES}/transform-hardlink.tar.bz2`, {
      type: "tar-bz2-to-zip",
      extension: "zip",
      require_paths: [],
      link_cache_bytes: 1024,
    });
    expect(meta.entryCount).toBe(2);
  });

  it("drops a symlink listed in drop_symlinks and records it; nothing else is dropped", async () => {
    const { bytes, meta } = await transformFixture(`${FIXTURES}/transform-symlink.tar.bz2`, {
      type: "tar-bz2-to-zip",
      extension: "zip",
      require_paths: [],
      drop_symlinks: ["bin/link.exe"],
    });
    expect(meta.droppedSymlinks).toEqual(["bin/link.exe"]);
    expect(meta.entryCount).toBe(1); // bin/real.exe only — a symlink is not a file entry
    const entries = readZipEntries(bytes);
    expect([...entries.keys()].sort()).toEqual(["bin/real.exe"]);
  });

  it("fails on a symlink not covered by drop_symlinks, naming the link target", async () => {
    await expect(
      transformFixture(`${FIXTURES}/transform-symlink.tar.bz2`, {
        type: "tar-bz2-to-zip",
        extension: "zip",
        require_paths: [],
        drop_symlinks: ["some/other/path"],
      }),
    ).rejects.toThrow(/symlink -> real\.exe \(not listed in drop_symlinks\)/);
  });

  it("records require_paths misses in the meta rather than failing the stream", async () => {
    const config: TransformConfig = {
      type: "tar-bz2-to-zip",
      extension: "zip",
      require_paths: ["cmd/git.exe", "missing/thing.txt"],
    };
    const { meta } = await transformFixture(`${FIXTURES}/transform-basic.tar.bz2`, config);
    expect(meta.pathsPresent).toEqual(["cmd/git.exe"]);
    expect(meta.pathsMissing).toEqual(["missing/thing.txt"]);
    const problems = checkGate(meta, config);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/missing required path\(s\): missing\/thing\.txt/);
  });

  it("checkGate enforces min_entries with a message naming the shortfall", () => {
    const meta = { entryCount: 5, pathsPresent: [], pathsMissing: [] };
    const problems = checkGate(meta, {
      type: "tar-bz2-to-zip",
      extension: "zip",
      require_paths: [],
      min_entries: 3000,
    });
    expect(problems).toHaveLength(1);
    expect(problems[0]).toMatch(/holds 5 entries, below the required minimum of 3000/);
  });

  it("the registry resolves the family name to a versioned identity", () => {
    expect(getTransform("tar-bz2-to-zip").id).toBe(TAR_BZ2_TO_ZIP_ID);
    expect(() => getTransform("tar-gz-to-zip")).toThrow(/unknown transform type/);
  });

  it("renders the served filename from the transform's own template", () => {
    const platform = { os: "windows" as const, arch: "x86-64" as const, extension: "tar.bz2" };
    expect(
      renderServedFilename(
        {
          type: "tar-bz2-to-zip",
          extension: "zip",
          require_paths: [],
          filename_template: "Git-{version}-{os}-{arch}.zip",
        },
        platform,
        "2.55.0.5",
        "Git-2.55.0.5-64-bit.tar.bz2",
      ),
    ).toBe("Git-2.55.0.5-windows-x86-64.zip");
    // Without a template, the upstream stem survives and the extension swaps.
    expect(
      renderServedFilename(
        { type: "tar-bz2-to-zip", extension: "zip", require_paths: [] },
        platform,
        "2.55.0.5",
        "Git-2.55.0.5-64-bit.tar.bz2",
      ),
    ).toBe("Git-2.55.0.5-64-bit.zip");
  });

  describe("streaming (WAL-57 AC2)", () => {
    const SIZE = 160 * 1024 * 1024;

    function hasBzip2(): boolean {
      try {
        execSync("bzip2 --help", { stdio: "ignore" });
        return true;
      } catch {
        return false;
      }
    }

    /**
     * Generate a large tar of alternating pseudo-random (incompressible) and zero blocks so
     * the memory assertion cannot pass by accident on either side of the pipeline, then
     * compress with the system bzip2. Generated per run — nothing close to this size is
     * ever checked in.
     */
    async function makeLargeFixture(dir: string): Promise<string> {
      const pack = tar.pack();
      const tarPath = path.join(dir, "large.tar");
      const tarFile = fs.createWriteStream(tarPath);
      const { pipeline } = await import("stream/promises");
      const pipeDone = pipeline(pack as never, tarFile);

      const entrySize = 4 * 1024 * 1024;
      const block = Buffer.alloc(64 * 1024);
      let seed = 0x9e3779b9;
      const nextBlock = (): Buffer => {
        for (let i = 0; i < block.length; i += 4) {
          seed = (seed * 1103515245 + 12345) & 0x7fffffff;
          block.writeUInt32LE(seed, i);
        }
        return block;
      };

      const entryCount = Math.floor(SIZE / entrySize);
      for (let e = 0; e < entryCount; e += 1) {
        const entry = pack.entry(
          { name: `blob/dir${e % 4}/file-${e}.bin`, size: entrySize, mtime: new Date(0) },
          (err?: Error | null) => {
            if (err) throw err;
          },
        );
        for (let written = 0; written < entrySize; written += block.length) {
          entry.write(e % 2 === 0 ? nextBlock() : Buffer.alloc(block.length));
        }
        entry.end();
      }
      pack.finalize();
      await pipeDone;

      execSync(`bzip2 -1 -c ${tarPath} > ${tarPath}.bz2`);
      fs.rmSync(tarPath, { force: true });
      return `${tarPath}.bz2`;
    }

    it("a ~160 MB tree transforms without buffering the archive or the output", async () => {
      if (!hasBzip2()) {
        console.warn("bzip2 not available — skipping large-fixture streaming test");
        return;
      }
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-large-"));
      try {
        const fixture = await makeLargeFixture(dir);
        const inputSize = fs.statSync(fixture).size;
        const entryCount = Math.floor(SIZE / (4 * 1024 * 1024));

        const sampler = new BufferMemorySampler();

        const transform = new TarBz2ToZipTransform();
        // Count how much of the source has flowed out, so interleaving can be asserted:
        // a transform that buffers would swallow the whole source before emitting anything.
        let sourceConsumed = 0;
        const raw = fs.createReadStream(fixture);
        raw.on("data", (chunk: Buffer) => {
          sourceConsumed += chunk.length;
        });
        const { output, meta } = transform.apply(raw, {
          type: "tar-bz2-to-zip",
          extension: "zip",
          require_paths: [],
        });

        let outputProduced = 0;
        let sourceConsumedAtFirstOutput = -1;
        const probe = new PassThrough();
        probe.on("data", (chunk: Buffer) => {
          if (sourceConsumedAtFirstOutput < 0 && outputProduced >= 1024 * 1024) {
            sourceConsumedAtFirstOutput = sourceConsumed;
          }
          outputProduced += chunk.length;
        });
        output.pipe(probe);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        for await (const _chunk of probe) {
          /* counted above */
        }
        const result = await meta;

        expect(result.entryCount).toBe(entryCount);
        expect(outputProduced).toBeGreaterThan(1024 * 1024);
        // Streaming interleaves: by the time the first megabyte of zip has emerged, the
        // source must not have been swallowed whole.
        expect(sourceConsumedAtFirstOutput).toBeGreaterThan(0);
        expect(sourceConsumedAtFirstOutput).toBeLessThan(inputSize);
        // And peak retained memory must be nowhere near either side's size. Sampled as
        // external + arrayBuffers, NOT heapUsed: Node Buffers live off the V8 heap, so a
        // heapUsed assertion here would pass while gigabytes of archive sat in memory.
        expect(sampler.peakBytes()).toBeLessThan(128 * 1024 * 1024);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }, 240_000);

    const LINK_TARGET_SIZE = 2 * 1024 * 1024;
    const LINK_RUN_LENGTH = 32;

    /**
     * One incompressible target followed by an unbroken run of hardlinks to it — the shape
     * of `libexec/git-core/*` in the Git for Windows tree, where ~90 links point at one
     * multi-MB binary. Hardlinks carry no content in the tar, so the input stays ~2 MB while
     * the output is the target repeated `LINK_RUN_LENGTH` times.
     */
    async function makeHardlinkRunFixture(dir: string): Promise<string> {
      const pack = tar.pack();
      const tarPath = path.join(dir, "hardlink-run.tar");
      const { pipeline } = await import("stream/promises");
      const pipeDone = pipeline(pack as never, fs.createWriteStream(tarPath));

      const target = Buffer.alloc(LINK_TARGET_SIZE);
      let seed = 0x9e3779b9;
      for (let i = 0; i < LINK_TARGET_SIZE; i += 4) {
        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
        target.writeUInt32LE(seed, i);
      }
      pack.entry({ name: "bin/git.exe", size: LINK_TARGET_SIZE, mtime: new Date(0) }, target);
      for (let i = 0; i < LINK_RUN_LENGTH; i += 1) {
        pack.entry({
          name: `libexec/git-core/git-cmd${i}.exe`,
          type: "link",
          linkname: "bin/git.exe",
          mtime: new Date(0),
        });
      }
      pack.finalize();
      await pipeDone;

      execSync(`bzip2 -1 -c ${tarPath} > ${tarPath}.bz2`);
      fs.rmSync(tarPath, { force: true });
      return `${tarPath}.bz2`;
    }

    /**
     * Regression: hardlink duplicates used to reach yazl via `addBuffer`, which deflates
     * eagerly and writes through without honouring backpressure, and `next()` was called
     * synchronously straight after. A run of consecutive links therefore queued one
     * compressed copy each regardless of how fast storage was draining — peak memory scaled
     * with the run length, not with the link cache, and reached ~1.9 GB against a 64 MiB
     * cache budget. Nothing caught it: the large-fixture test above has no hardlinks, and
     * `validate --transform` drains into a null sink as fast as it can, so no backpressure
     * ever builds there.
     */
    it("a run of hardlinks stays bounded against a slow consumer", async () => {
      if (!hasBzip2()) {
        console.warn("bzip2 not available — skipping hardlink backpressure test");
        return;
      }
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-hlrun-"));
      try {
        const fixture = await makeHardlinkRunFixture(dir);
        const sampler = new BufferMemorySampler();

        const transform = new TarBz2ToZipTransform();
        const { output, meta } = transform.apply(fs.createReadStream(fixture), {
          type: "tar-bz2-to-zip",
          extension: "zip",
          require_paths: [],
          // Sized to hold the target and nothing more, so anything above this is queueing.
          link_cache_bytes: 4 * 1024 * 1024,
        });

        // Drain deliberately slower than the transform can produce (~15 MB/s against a
        // deflate that manages several times that), so the output stays backpressured for
        // the whole run. A full stop would not do: the target is a regular file, and its
        // own correctly-backpressured entry would hold the tar parser before the hardlink
        // run was ever reached.
        let outputProduced = 0;
        const bytesPerSecond = 25 * 1024 * 1024;
        const slow = new Transform({
          highWaterMark: 256 * 1024,
          transform(chunk: Buffer, _enc, cb) {
            outputProduced += chunk.length;
            // Paced by bytes, not per chunk: chunk sizes vary widely down the pipeline, so
            // a fixed per-chunk delay makes the test's duration depend on chunking.
            setTimeout(() => cb(null, chunk), (chunk.length / bytesPerSecond) * 1000);
          },
        });
        output.pipe(slow);
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        for await (const _chunk of slow) {
          /* counted above */
        }
        const result = await meta;
        const peakUnderBackpressure = sampler.peakBytes();

        expect(result.entryCount).toBe(LINK_RUN_LENGTH + 1);
        // The run really is duplicated into the output — the bound is not bought by
        // dropping entries. Deflate shrinks the target a little, so compare against a
        // multiple of it rather than the raw total: a dropped run would be ~one target.
        expect(outputProduced).toBeGreaterThan(10 * LINK_TARGET_SIZE);
        // A backpressured consumer must hold the pipeline near the link cache, not near
        // the whole run. Measured on this fixture: ~31 MB with the streaming hardlink path,
        // ~238 MB when hardlinks go through `addBuffer` instead. 64 MiB sits well clear of
        // the former and well below the latter.
        expect(peakUnderBackpressure).toBeLessThan(64 * 1024 * 1024);
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    }, 120_000);
  });
});
