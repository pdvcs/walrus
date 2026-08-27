import { Readable } from "stream";

/**
 * An inclusive byte range, matching both `fs.createReadStream` and the GCS client — `end` is
 * the last byte returned, not one past it, which is also how HTTP `Range` counts.
 */
export interface ByteRange {
  start: number;
  end: number;
}

export interface StorageBackend {
  upload: (key: string, stream: Readable) => Promise<void>;
  download: (key: string) => Promise<Buffer>;
  /** Omit `range` for the whole object; pass one to read only those bytes from storage. */
  stream: (key: string, range?: ByteRange) => Readable;
  delete: (key: string) => Promise<void>;
  exists: (key: string) => Promise<boolean>;
}

export interface ArtifactPathParts {
  packageName: string;
  version: string;
  os: string;
  arch: string;
  filename: string;
}

export function buildArtifactPath(parts: ArtifactPathParts): string {
  return `${parts.packageName}/${parts.version}/${parts.os}/${parts.arch}/${parts.filename}`;
}
