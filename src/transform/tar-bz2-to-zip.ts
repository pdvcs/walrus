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

/**
 * Bounded, insertion-ordered (oldest-evicted) store of file entry content, keyed by path.
 *
 * Space is taken by `reserve` *before* an entry's content is collected, not by a `put`
 * afterwards, so the collector's in-flight copy is counted against the same budget as the
 * stored ones. That is what makes the budget a true ceiling: charging only on store left the
 * in-flight copy outside the accounting, and the real bound was `budget + 2 × largest cached
 * file` while the config, the Terraform memory pin and the changelog all asserted `budget`
 * (WAL-73 finding 6).
 *
 * Entries are processed strictly one at a time, so evicting at reservation rather than at
 * store cannot change which entries a hardlink finds — no `get` happens in between. It does
 * mean the budget must cover the hardlink's target, everything between them, *and* the entry
 * currently being collected; that was always the memory cost, it is now also the arithmetic.
 *
 * Exported for the accounting tests: the invariant is what changed, and it is not observable
 * from the transform's output.
 */
export class LinkCache {
  private total = 0;
  /** `reserved` is what the entry costs the budget; `content` may be a shorter view of it. */
  private readonly entries = new Map<string, { content: Buffer; reserved: number }>();

  constructor(private readonly budget: number) {}

  /**
   * Charge `size` bytes to the budget, evicting oldest entries to make room. Returns false —
   * having reserved nothing — when the entry could never fit whatever were evicted.
   */
  reserve(size: number): boolean {
    if (size > this.budget) return false;
    while (this.total + size > this.budget && this.entries.size > 0) {
      const oldest = this.entries.keys().next().value as string;
      this.total -= this.entries.get(oldest)!.reserved;
      this.entries.delete(oldest);
    }
    this.total += size;
    return true;
  }

  /** Hand back a reservation whose content will not be stored after all. */
  release(size: number): void {
    this.total -= size;
  }

  /** Store content against a live reservation of `reserved` bytes. */
  commit(name: string, content: Buffer, reserved: number): void {
    const previous = this.entries.get(name);
    // A duplicate path re-uses the new reservation; the old copy's charge retires with it.
    if (previous !== undefined) this.total -= previous.reserved;
    this.entries.set(name, { content, reserved });
  }

  get(name: string): Buffer | undefined {
    return this.entries.get(name)?.content;
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
      // One allocation of the size the tar header declares, filled in place. Collecting into
      // a chunk array and concatenating at flush transiently held two copies of the entry
      // *on top of* a full cache; reserving the space up front and copying into it keeps the
      // budget an actual ceiling (WAL-73 finding 6).
      const declaredSize = header.size ?? 0;
      let collected: Buffer | null = cache.reserve(declaredSize)
        ? Buffer.allocUnsafe(declaredSize)
        : null;
      let filled = 0;
      const abandon = (): void => {
        if (collected === null) return;
        collected = null;
        cache.release(declaredSize);
      };
      const collector = new Transform({
        transform(chunk: Buffer, _enc, cb) {
          if (collected !== null) {
            // An entry longer than its own header is not something the reservation describes.
            if (filled + chunk.length > collected.length) {
              abandon();
            } else {
              chunk.copy(collected, filled);
              filled += chunk.length;
            }
          }
          cb(null, chunk);
        },
        flush(cb) {
          if (collected !== null) {
            // Cache even empty files: a hardlink to one must still resolve to empty content.
            // A short entry is stored as a view — `subarray` shares the allocation, so the
            // reservation, not the view's length, is what stays charged.
            const content = filled === collected.length ? collected : collected.subarray(0, filled);
            cache.commit(name, content, declaredSize);
          }
          // Drop the collector's own reference either way. yazl retains every Entry until it
          // writes the central directory, and an Entry retains its read stream — which is this
          // collector, which closes over `collected`. Without this every entry's content stays
          // reachable for the whole archive, so peak memory tracks total archive size rather
          // than the link cache budget (measured: 307 MB on a 160 MB tree against a 64 MiB
          // budget). What the cache kept is accounted for by its own reservation.
          collected = null;
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
