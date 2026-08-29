import { PassThrough, Transform, Readable } from "stream";
import { pipeline } from "stream/promises";
import unbzip2Stream from "unbzip2-stream";
import tar from "tar-stream";
import yazl from "yazl";
import { ArchiveTransform, TransformResultMeta, TransformedStream } from "./types.js";
import { TransformConfig } from "../types/package-config.js";

/**
 * Git for Windows publishes the full portable tree as `Git-<version>-<arch>.tar.bz2` — the
 * same tree the `.7z.exe` wraps, in a container that streams. This transform rewrites that
 * stream into a zip without ever holding the archive or the output in memory:
 *
 *   tar.bz2 → bunzip2 → tar-parse → zip-write
 *
 * Zip has no hardlink concept, so hardlink entries (tar type `link`) resolve by duplicating
 * the target's content from a bounded cache of recently seen file entries. A hardlink whose
 * target is not in the cache is a hard failure: a zip that extracts and then misbehaves is
 * the worst available outcome, so anything not understood fails the artifact instead.
 *
 * Flow control: every entry — regular file and hardlink duplicate alike — reaches yazl as a
 * read stream, and the tar parser is released (`next()`) only once yazl has drained it. That
 * is load-bearing, not stylistic. yazl honours backpressure on exactly one path: read-stream
 * entries are piped into the output, while `addBuffer` deflates the whole entry eagerly and
 * then writes it through without checking `write()`'s return value. Adding hardlinks by
 * buffer let a run of consecutive links — `libexec/git-core/*` is precisely that, ~90 links
 * to one multi-MB binary — queue a compressed copy each no matter how slowly storage was
 * draining, making peak memory scale with the run instead of with the link cache.
 *
 * Determinism: fixed deflate level, tar entry order preserved, mtime from the tar header,
 * no added extra fields, zip64 only where yazl's size thresholds require it. The identity is
 * versioned so a change to this file is distinguishable from a change upstream.
 */
export const TAR_BZ2_TO_ZIP_ID = "tar-bz2-to-zip@1";

/** Fixed deflate level — the same input must yield byte-identical output across re-syncs. */
const DEFLATE_LEVEL = 6;

/**
 * Content of recently seen file entries, retained so a `link` entry can duplicate its
 * target. The budget bounds memory: it never scales with artifact size beyond this constant,
 * and is configurable per package (`link_cache_bytes`) because the required window is a
 * property of the real archive — measured, not guessed. A hardlink whose target is not in
 * the cache is a hard failure naming the gap.
 */
const DEFAULT_LINK_CACHE_BUDGET_BYTES = 64 * 1024 * 1024;

export class UnsupportedEntryTypeError extends Error {
  constructor(entryName: string, entryType: string) {
    super(
      `unsupported tar entry type '${entryType}' for '${entryName}': the transform would ` +
        `drop it from the zip, so the artifact fails instead of extracting broken`,
    );
    this.name = "UnsupportedEntryTypeError";
  }
}

export class UnresolvableHardlinkError extends Error {
  constructor(entryName: string, linkname: string) {
    super(
      `hardlink '${entryName}' -> '${linkname}': target content not retained. The target must ` +
        `appear before its hardlink within the transform's link cache window`,
    );
    this.name = "UnresolvableHardlinkError";
  }
}

/** What the entry handler needs of a tar-stream entry stream (tar-stream is streamx-based). */
interface TarEntryStream {
  pipe<T>(dest: T): T;
  resume(): void;
  on(event: "end", listener: () => void): unknown;
}

/** Bounded, insertion-ordered (oldest-evicted) store of file entry content, keyed by path. */
class LinkCache {
  private total = 0;
  private readonly entries = new Map<string, Buffer>();

  constructor(private readonly budget: number) {}

  wouldFit(size: number): boolean {
    return size <= this.budget;
  }

  put(name: string, content: Buffer): void {
    while (this.total + content.length > this.budget && this.entries.size > 0) {
      const oldest = this.entries.keys().next().value as string;
      this.total -= this.entries.get(oldest)!.length;
      this.entries.delete(oldest);
    }
    if (this.total + content.length > this.budget) return;
    this.entries.set(name, content);
    this.total += content.length;
  }

  get(name: string): Buffer | undefined {
    return this.entries.get(name);
  }
}

export class TarBz2ToZipTransform implements ArchiveTransform {
  readonly id = TAR_BZ2_TO_ZIP_ID;

  apply(source: Readable, config: TransformConfig): TransformedStream {
    if (config.type !== "tar-bz2-to-zip") {
      throw new Error(`tar-bz2-to-zip transform given config type '${String(config.type)}'`);
    }

    const cache = new LinkCache(config.link_cache_bytes ?? DEFAULT_LINK_CACHE_BUDGET_BYTES);
    const zip = new yazl.ZipFile();
    const extract = tar.extract();
    const required = new Set(config.require_paths);
    const droppableSymlinks = new Set(config.drop_symlinks ?? []);
    const droppedSymlinks: string[] = [];

    let entryCount = 0;

    let metaReject: (err: Error) => void = () => {};
    let metaResolve: (meta: TransformResultMeta) => void = () => {};
    const meta = new Promise<TransformResultMeta>((resolve, reject) => {
      metaResolve = resolve;
      metaReject = reject;
    });
    // The caller usually awaits meta only after the upload settles; mark it handled so a
    // failure that surfaces through the upload's own rejection cannot also crash the
    // process as an unhandled rejection.
    meta.catch(() => {});

    let failed = false;
    const fail = (err: Error): void => {
      if (failed) return;
      failed = true;
      metaReject(err);
      source.destroy(err);
      extract.destroy(err);
      (zip.outputStream as unknown as Readable).destroy(err);
    };

    extract.on("entry", (header, entryStream, next) => {
      try {
        handleEntry(header, entryStream, next);
      } catch (err) {
        fail(err instanceof Error ? err : new Error(String(err)));
      }
    });

    const handleEntry = (
      header: tar.Header,
      entryStream: TarEntryStream,
      next: () => void,
    ): void => {
      const name = normalizeEntryName(header.name);
      if (name === null || name === "") {
        fail(new Error(`tar entry has an unusable name: '${header.name}'`));
        return;
      }
      const mtime = header.mtime ?? new Date(0);
      const mode = header.mode ?? 0o644;

      switch (header.type) {
        case "directory":
          // A zip recreates directories implicitly from file paths; skip without counting.
          entryStream.resume();
          entryStream.on("end", next);
          return;
        case "file":
          break;
        case "symlink":
          // Default is the hard failure WAL-57 AC4 demands. A drop is allowed only where the
          // config explicitly names the path — and it is recorded, never silent.
          if (droppableSymlinks.has(name)) {
            droppedSymlinks.push(name);
            entryStream.resume();
            entryStream.on("end", next);
            return;
          }
          fail(
            new UnsupportedEntryTypeError(
              name,
              `${header.type} -> ${header.linkname ?? ""} (not listed in drop_symlinks)`,
            ),
          );
          return;
        case "link": {
          const target = normalizeEntryName(header.linkname ?? "");
          const content = target === null ? undefined : cache.get(target);
          if (content === undefined) {
            fail(new UnresolvableHardlinkError(name, header.linkname ?? ""));
            return;
          }
          entryCount += 1;
          required.delete(name);
          // Handed to yazl as a stream, not a buffer, so the duplicate obeys the same
          // backpressure every other entry does — see "Flow control" above.
          const linkStream = chunkedStream(content);
          linkStream.on("end", next);
          zip.addReadStream(linkStream, name, {
            mtime,
            mode,
            size: content.length,
            compressionLevel: DEFLATE_LEVEL,
          });
          return;
        }
        default:
          fail(new UnsupportedEntryTypeError(name, String(header.type)));
          return;
      }

      // Regular file. Tee the entry through a bounded collector so its content can resolve a
      // later hardlink, while yazl's own backpressure governs the flow.
      entryCount += 1;
      required.delete(name);
      const pending: Buffer[] = [];
      let pendingSize = 0;
      let cacheable = cache.wouldFit(header.size ?? 0);
      const collector = new Transform({
        transform(chunk: Buffer, _enc, cb) {
          if (cacheable && cache.wouldFit(pendingSize + chunk.length)) {
            pending.push(chunk);
            pendingSize += chunk.length;
          } else {
            cacheable = false;
          }
          cb(null, chunk);
        },
        flush(cb) {
          // Cache even empty files: a hardlink to one must still resolve to empty content.
          if (cacheable) cache.put(name, Buffer.concat(pending));
          // Drop the chunk references. yazl retains every Entry until it writes the central
          // directory, and an Entry retains its read stream — which is this collector, which
          // closes over `pending`. Without this the collected chunks of every entry stay
          // reachable for the whole archive, so peak memory tracks total archive size rather
          // than the link cache budget (measured: 307 MB on a 160 MB tree against a 64 MiB
          // budget). The cache keeps its own concatenated copy, which `total` accounts for.
          pending.length = 0;
          pendingSize = 0;
          cb();
        },
      });
      const piped = entryStream.pipe(collector);
      piped.on("end", next);
      zip.addReadStream(piped, name, {
        mtime,
        mode,
        size: header.size,
        compressionLevel: DEFLATE_LEVEL,
      });
    };

    extract.on("finish", () => {
      if (failed) return;
      zip.end();
      metaResolve({
        entryCount,
        pathsPresent: config.require_paths.filter((p) => !required.has(p)),
        pathsMissing: config.require_paths.filter((p) => required.has(p)),
        droppedSymlinks,
      });
    });

    source.on("error", (err) => fail(err instanceof Error ? err : new Error(String(err))));
    extract.on("error", (err) => fail(err instanceof Error ? err : new Error(String(err))));
    zip.on("error", (err) => fail(err instanceof Error ? err : new Error(String(err))));

    // The wrapper pass-through makes an upstream yazl failure surface as an error on the
    // output stream, so the storage upload rejects instead of waiting forever for an end
    // that will never come.
    const output = new PassThrough();
    pipeline(zip.outputStream as unknown as Readable, output).catch(() => {
      /* the error has already been raised through fail() and the output stream */
    });

    // unbzip2() is a factory: source bytes flow through the decoder into the tar parser.
    source.pipe(unbzip2Stream()).pipe(extract);

    return { output, meta };
  }
}

/**
 * A cached buffer replayed in file-sized pieces. Pushing it as one chunk would be correct
 * but wasteful: yazl's read-stream path runs each chunk through a crc32 watcher, two byte
 * counters and a deflate, so a single multi-MB write balloons through the chain where a
 * real file entry arrives in stream-sized pieces. `subarray` is a view — nothing is copied.
 */
const LINK_CHUNK_BYTES = 64 * 1024;

function chunkedStream(content: Buffer): Readable {
  let offset = 0;
  return new Readable({
    read() {
      if (offset >= content.length) {
        this.push(null);
        return;
      }
      const end = Math.min(offset + LINK_CHUNK_BYTES, content.length);
      this.push(content.subarray(offset, end));
      offset = end;
    },
  });
}

/** Strip `./` prefixes and absolute roots; reject traversal and separator oddities. */
function normalizeEntryName(name: string): string | null {
  if (name.includes("\\")) return null;
  let normalized = name;
  while (normalized.startsWith("./")) normalized = normalized.slice(2);
  while (normalized.startsWith("/")) normalized = normalized.slice(1);
  if (normalized.split("/").some((segment) => segment === "..")) return null;
  return normalized.replace(/\/+$/, "");
}
