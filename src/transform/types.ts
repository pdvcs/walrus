import { Readable } from "stream";
import { TransformConfig } from "../types/package-config.js";

/**
 * What a transform observed while producing its output. Resolves once the source stream is
 * fully consumed and the transformed archive is complete; rejects on any hard failure.
 * `require_paths` / `min_entries` are *recorded* here and *enforced* by the caller via
 * `checkGate` — enforcement is deliberately outside the stream, so a failure can name what
 * was missing after the pipeline has wound down.
 */
export interface TransformResultMeta {
  /** File entries written to the output archive (directories are not entries). */
  entryCount: number;
  pathsPresent: string[];
  pathsMissing: string[];
  /**
   * Symlink entries dropped because the config's `drop_symlinks` listed them. Recorded so a
   * drop is never silent; any symlink NOT listed is a hard failure (WAL-57 AC4).
   */
  droppedSymlinks: string[];
}

export interface TransformedStream {
  output: Readable;
  meta: Promise<TransformResultMeta>;
}

/**
 * One archive conversion, shaped like a DiscoveryStrategy: a normalized interface, one file
 * per conversion in src/transform/, nothing else in the pipeline knows the container formats
 * involved. Implementations must stream — peak memory may not scale with artifact size — and
 * must be deterministic: the same source bytes always yield identical output bytes.
 */
export interface ArchiveTransform {
  /** Versioned identity recorded on the artifact, e.g. "tar-bz2-to-zip@1". */
  readonly id: string;
  apply(source: Readable, config: TransformConfig): TransformedStream;
}
