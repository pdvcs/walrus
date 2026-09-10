import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RustChannelStrategy } from "../../src/discovery/rust-channel.js";
import { PackageConfigSchema, PackageConfig } from "../../src/types/package-config.js";
import { log } from "../../src/common/log.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

const TRIPLES = [
  "x86_64-unknown-linux-gnu",
  "aarch64-unknown-linux-gnu",
  "x86_64-apple-darwin",
  "aarch64-apple-darwin",
  "x86_64-pc-windows-msvc",
  "aarch64-pc-windows-msvc",
];

const LISTING_URL = "https://static.rust-lang.org/?list-type=2&prefix=dist/channel-rust-";
const MANIFEST_TEMPLATE = "https://static.rust-lang.org/dist/channel-rust-{version}.toml";

/** Six platforms: arch_upstream + os_upstream form the Rust target triple (arch first). */
const PLATFORMS: PackageConfig["platforms"] = [
  {
    os: "linux",
    arch: "x86-64",
    os_upstream: "unknown-linux-gnu",
    arch_upstream: "x86_64",
    extension: "tar.gz",
  },
  {
    os: "linux",
    arch: "arm64",
    os_upstream: "unknown-linux-gnu",
    arch_upstream: "aarch64",
    extension: "tar.gz",
  },
  {
    os: "macos",
    arch: "x86-64",
    os_upstream: "apple-darwin",
    arch_upstream: "x86_64",
    extension: "tar.gz",
  },
  {
    os: "macos",
    arch: "arm64",
    os_upstream: "apple-darwin",
    arch_upstream: "aarch64",
    extension: "tar.gz",
  },
  {
    os: "windows",
    arch: "x86-64",
    os_upstream: "pc-windows-msvc",
    arch_upstream: "x86_64",
    extension: "tar.gz",
  },
  {
    os: "windows",
    arch: "arm64",
    os_upstream: "pc-windows-msvc",
    arch_upstream: "aarch64",
    extension: "tar.gz",
  },
];

const RUST_CONFIG: PackageConfig = {
  name: "rust",
  display_name: "Rust",
  vendor: "The Rust Project",
  discovery: {
    type: "rust-channel",
    listing_url: LISTING_URL,
    manifest_url_template: MANIFEST_TEMPLATE,
    max_versions: 10,
    package: "rust",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    min_version: "1.90",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2, groups_to_keep: 3 },
  platforms: PLATFORMS,
};

function buildManifest(
  version: string,
  date: string,
  opts: { unavailable?: string[] } = {},
): string {
  const lines = [
    'manifest-version = "2"',
    `date = "${date}"`,
    "",
    "[pkg.rust]",
    `version = "${version} (48a229cea 2026-09-01)"`,
    'git_commit_hash = "48a229ceaefd4985c50990b14116b6d856af0985"',
    "",
  ];
  const unavailable = new Set(opts.unavailable ?? []);
  for (const triple of TRIPLES) {
    const base = `https://static.rust-lang.org/dist/${date}/rust-${version}-${triple}`;
    lines.push(`[pkg.rust.target.${triple}]`);
    lines.push(`available = ${unavailable.has(triple) ? "false" : "true"}`);
    lines.push(`url = "${base}.tar.gz"`);
    lines.push(`hash = "gz-${version}-${triple}"`);
    lines.push(`xz_url = "${base}.tar.xz"`);
    lines.push(`xz_hash = "xz-${version}-${triple}"`);
    lines.push("");
  }
  return lines.join("\n");
}

function buildListing(versions: string[], nextToken?: string): string {
  const contents = versions
    .flatMap((v) => [
      `<Contents><Key>dist/channel-rust-${v}.toml</Key><Size>900000</Size></Contents>`,
      `<Contents><Key>dist/channel-rust-${v}.toml.asc</Key><Size>800</Size></Contents>`,
      `<Contents><Key>dist/channel-rust-${v}.toml.sha256</Key><Size>80</Size></Contents>`,
    ])
    .join("");
  const token = nextToken ? `<NextContinuationToken>${nextToken}</NextContinuationToken>` : "";
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>static-rust-lang-org</Name>
  <Prefix>dist/channel-rust-</Prefix>
  <IsTruncated>${nextToken ? "true" : "false"}</IsTruncated>
  ${token}
  ${contents}
</ListBucketResult>`;
}

function okText(body: string): Response {
  return { ok: true, status: 200, headers: new Headers(), text: async () => body } as Response;
}

function httpError(status: number): Response {
  return { ok: false, status, headers: new Headers(), text: async () => "error" } as Response;
}

interface StubOptions {
  pages: string[];
  manifests: Record<string, string>;
  failListing?: number;
}

/** Routes listing (S3 XML, possibly paginated) and per-version TOML manifests. */
function stubFetch(options: StubOptions): void {
  let listingCall = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: Request | string | URL) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (url.includes("list-type=2")) {
        if (options.failListing) return httpError(options.failListing);
        const body = options.pages[listingCall] ?? "";
        listingCall += 1;
        return okText(body);
      }

      const match = /channel-rust-([\d.]+)\.toml/.exec(url);
      const manifest = match ? options.manifests[match[1]] : undefined;
      return manifest === undefined ? httpError(404) : okText(manifest);
    }),
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ── Discovery ───────────────────────────────────────────────────────────────

describe("RustChannelStrategy", () => {
  it("discovers versions newest-first with gzip artifacts and the manifest date", async () => {
    stubFetch({
      pages: [buildListing(["1.97.1", "1.98.0", "1.98.1"])],
      manifests: {
        "1.98.1": buildManifest("1.98.1", "2026-09-03"),
        "1.98.0": buildManifest("1.98.0", "2026-08-20"),
        "1.97.1": buildManifest("1.97.1", "2026-08-06"),
      },
    });

    const versions = await new RustChannelStrategy().discoverVersions(RUST_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["1.98.1", "1.98.0", "1.97.1"]);
    expect(versions.map((v) => v.versionGroup)).toEqual(["1.98", "1.98", "1.97"]);

    const latest = versions[0];
    expect(latest.artifacts.size).toBe(6);
    expect(latest.releasedAt).toEqual(new Date("2026-09-03"));

    const linux = latest.artifacts.get("linux/x86-64")!;
    expect(linux.filename).toBe("rust-1.98.1-x86_64-unknown-linux-gnu.tar.gz");
    expect(linux.url).toBe(
      "https://static.rust-lang.org/dist/2026-09-03/rust-1.98.1-x86_64-unknown-linux-gnu.tar.gz",
    );
    expect(linux.checksum).toBe("gz-1.98.1-x86_64-unknown-linux-gnu");
    expect(linux.checksumType).toBe("sha256");
  });

  it("selects the xz artifact when the platform extension is tar.xz", async () => {
    stubFetch({
      pages: [buildListing(["1.98.1"])],
      manifests: { "1.98.1": buildManifest("1.98.1", "2026-09-03") },
    });
    const config: PackageConfig = {
      ...RUST_CONFIG,
      platforms: PLATFORMS.map((p) =>
        p.os === "macos" && p.arch === "arm64" ? { ...p, extension: "tar.xz" } : p,
      ),
    };

    const versions = await new RustChannelStrategy().discoverVersions(config);

    const mac = versions[0].artifacts.get("macos/arm64")!;
    expect(mac.url).toBe(
      "https://static.rust-lang.org/dist/2026-09-03/rust-1.98.1-aarch64-apple-darwin.tar.xz",
    );
    expect(mac.filename).toBe("rust-1.98.1-aarch64-apple-darwin.tar.xz");
    expect(mac.checksum).toBe("xz-1.98.1-aarch64-apple-darwin");
    // Platforms left on tar.gz still take the gzip fields.
    expect(versions[0].artifacts.get("linux/x86-64")!.checksum).toBe(
      "gz-1.98.1-x86_64-unknown-linux-gnu",
    );
  });

  it("applies min_version before fetching manifests", async () => {
    stubFetch({
      pages: [buildListing(["1.89.0", "1.90.0", "1.91.0"])],
      manifests: {
        "1.89.0": buildManifest("1.89.0", "2025-01-01"),
        "1.90.0": buildManifest("1.90.0", "2025-03-01"),
        "1.91.0": buildManifest("1.91.0", "2025-05-01"),
      },
    });

    const versions = await new RustChannelStrategy().discoverVersions(RUST_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["1.91.0", "1.90.0"]);
  });

  it("fetches only max_versions manifests", async () => {
    stubFetch({
      pages: [buildListing(["1.98.0", "1.97.1", "1.97.0"])],
      manifests: {
        "1.98.0": buildManifest("1.98.0", "2026-08-20"),
        "1.97.1": buildManifest("1.97.1", "2026-08-06"),
        "1.97.0": buildManifest("1.97.0", "2026-07-23"),
      },
    });
    const config: PackageConfig = {
      ...RUST_CONFIG,
      discovery: { ...RUST_CONFIG.discovery, max_versions: 1 } as PackageConfig["discovery"],
    };

    const versions = await new RustChannelStrategy().discoverVersions(config);

    expect(versions.map((v) => v.version)).toEqual(["1.98.0"]);
  });

  it("skips an unavailable target but keeps the others", async () => {
    stubFetch({
      pages: [buildListing(["1.98.1"])],
      manifests: {
        "1.98.1": buildManifest("1.98.1", "2026-09-03", {
          unavailable: ["aarch64-pc-windows-msvc"],
        }),
      },
    });
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);

    const versions = await new RustChannelStrategy().discoverVersions(RUST_CONFIG);

    expect(versions[0].artifacts.size).toBe(5);
    expect(versions[0].artifacts.has("windows/arm64")).toBe(false);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ triple: "aarch64-pc-windows-msvc" }),
      expect.stringContaining("target unavailable"),
    );
  });

  it("follows listing pagination via the continuation token", async () => {
    stubFetch({
      pages: [buildListing(["1.98.1"], "tok123"), buildListing(["1.97.1"])],
      manifests: {
        "1.98.1": buildManifest("1.98.1", "2026-09-03"),
        "1.97.1": buildManifest("1.97.1", "2026-08-06"),
      },
    });

    const versions = await new RustChannelStrategy().discoverVersions(RUST_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["1.98.1", "1.97.1"]);
  });

  it("skips a version whose manifest is missing and keeps the rest", async () => {
    stubFetch({
      pages: [buildListing(["1.98.1", "1.98.0", "1.97.1"])],
      manifests: {
        "1.98.1": buildManifest("1.98.1", "2026-09-03"),
        // 1.98.0 deliberately absent -> 404
        "1.97.1": buildManifest("1.97.1", "2026-08-06"),
      },
    });
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);

    const versions = await new RustChannelStrategy().discoverVersions(RUST_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["1.98.1", "1.97.1"]);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ version: "1.98.0" }),
      expect.stringContaining("failed to read manifest"),
    );
  });

  it("rejects when the listing request fails", async () => {
    stubFetch({ pages: [], manifests: {}, failListing: 400 });

    await expect(new RustChannelStrategy().discoverVersions(RUST_CONFIG)).rejects.toThrow("400");
  });

  it("rejects a config of the wrong discovery type", async () => {
    const config = {
      ...RUST_CONFIG,
      discovery: { type: "github-releases", repo: "rust-lang/rust", include_prereleases: false },
    } as PackageConfig;

    await expect(new RustChannelStrategy().discoverVersions(config)).rejects.toThrow(
      /rust-channel/,
    );
  });
});

// ── Schema ──────────────────────────────────────────────────────────────────

describe("rust-channel schema", () => {
  it("defaults package to rust and accepts the config shape", () => {
    const parsed = PackageConfigSchema.parse({
      name: "rust",
      display_name: "Rust",
      vendor: "The Rust Project",
      discovery: {
        type: "rust-channel",
        listing_url: LISTING_URL,
        manifest_url_template: MANIFEST_TEMPLATE,
      },
      versioning: { type: "semver", version_group_extract: "^(\\d+\\.\\d+)" },
      platforms: [PLATFORMS[0]],
    });

    expect(parsed.discovery.type).toBe("rust-channel");
    if (parsed.discovery.type === "rust-channel") {
      expect(parsed.discovery.package).toBe("rust");
    }
  });

  it("rejects an unknown artifact-bearing discovery type", () => {
    expect(() =>
      PackageConfigSchema.parse({
        name: "rust",
        display_name: "Rust",
        vendor: "The Rust Project",
        discovery: { type: "toml-api", url: "https://example.test" },
        versioning: { type: "semver", version_group_extract: "^(\\d+\\.\\d+)" },
        platforms: [PLATFORMS[0]],
      }),
    ).toThrow();
  });
});
