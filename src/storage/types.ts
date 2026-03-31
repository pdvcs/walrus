import { Readable } from "stream";

export interface StorageBackend {
  upload: (key: string, stream: Readable) => Promise<void>;
  download: (key: string) => Promise<Buffer>;
  stream: (key: string) => Readable;
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
