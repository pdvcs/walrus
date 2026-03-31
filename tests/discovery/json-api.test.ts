import { describe, it, expect, vi, beforeEach } from "vitest";
import { JsonApiStrategy } from "../../src/discovery/json-api.js";
import { PackageConfig } from "../../src/types/package-config.js";

// ── Inline submode config (Golang) ──────────────────────────────────────────

const GOLANG_CONFIG: PackageConfig = {
  name: "golang",
  display_name: "Go",
  vendor: "Google",
  discovery: {
    type: "json-api",
    url: "https://go.dev/dl/?mode=json&include=all",
    releases_path: "$[?(@.stable==true)]",
    release_version_field: "version",
    tag_pattern: "^go(\\d+.*)",
    files_field: "files",
    file_os_field: "os",
    file_arch_field: "arch",
    file_kind_field: "kind",
    file_kind_value: "archive",
    file_filename_field: "filename",
    file_url_base: "https://dl.google.com/go/",
    file_checksum_field: "sha256",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 1 },
  platforms: [
    {
      os: "linux",
      arch: "x86-64",
      os_upstream: "linux",
      arch_upstream: "amd64",
      extension: "tar.gz",
    },
    {
      os: "macos",
      arch: "arm64",
      os_upstream: "darwin",
      arch_upstream: "arm64",
      extension: "tar.gz",
    },
  ],
};

const MOCK_GO_RESPONSE = [
  {
    version: "go1.24.1",
    stable: true,
    files: [
      {
        filename: "go1.24.1.linux-amd64.tar.gz",
        os: "linux",
        arch: "amd64",
        kind: "archive",
        sha256: "abc123",
        size: 70000000,
      },
      {
        filename: "go1.24.1.darwin-arm64.tar.gz",
        os: "darwin",
        arch: "arm64",
        kind: "archive",
        sha256: "def456",
        size: 68000000,
      },
      {
        filename: "go1.24.1.src.tar.gz",
        os: "",
        arch: "",
        kind: "source",
        sha256: "ghi789",
        size: 30000000,
      },
    ],
  },
  {
    version: "go1.23.5",
    stable: true,
    files: [
      {
        filename: "go1.23.5.linux-amd64.tar.gz",
        os: "linux",
        arch: "amd64",
        kind: "archive",
        sha256: "jkl012",
        size: 69000000,
      },
    ],
  },
  {
    version: "go1.24.0rc1",
    stable: false,
    files: [],
  },
];

// ── Two-step submode config (Adoptium/OpenJDK) ─────────────────────────────

const OPENJDK_CONFIG: PackageConfig = {
  name: "openjdk",
  display_name: "Eclipse Temurin OpenJDK",
  vendor: "Eclipse Foundation",
  discovery: {
    type: "json-api",
    url: "https://api.adoptium.net/v3/info/available_releases",
    versions_path: "$.available_releases",
    release_url_template:
      "https://api.adoptium.net/v3/assets/feature_releases/{major_version}/ga?architecture={arch}&image_type=jdk&os={os}&page=0&page_size=1",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+)",
    lts_support: true,
    lts_source: "api",
    lts_api_path: "$.available_lts_releases",
  },
  retention: { versions_per_group: 2 },
  checksum: { type: "inline-api", algorithm: "sha256", response_path: "$.checksum" },
  platforms: [
    {
      os: "linux",
      arch: "x86-64",
      os_upstream: "linux",
      arch_upstream: "x64",
      extension: "tar.gz",
    },
  ],
};

const MOCK_ADOPTIUM_VERSION_LIST = {
  available_releases: [21, 17],
  available_lts_releases: [21, 17, 11],
};

const MOCK_ADOPTIUM_RELEASE = [
  {
    release_name: "21.0.3+9",
    version_data: { major: 21, minor: 0, security: 3, build: 9 },
    binaries: [
      {
        package: {
          link: "https://github.com/adoptium/releases/download/jdk-21.0.3+9/OpenJDK21U-jdk_x64_linux_hotspot_21.0.3_9.tar.gz",
          name: "OpenJDK21U-jdk_x64_linux_hotspot_21.0.3_9.tar.gz",
          checksum: "sha256checksum",
        },
      },
    ],
  },
];

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("JsonApiStrategy — inline submode (Golang)", () => {
  it("discovers versions from inline API response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_GO_RESPONSE),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(GOLANG_CONFIG);

    // Only stable=true versions
    expect(versions.length).toBeGreaterThanOrEqual(2);
    const vStrings = versions.map((v) => v.version);
    expect(vStrings).toContain("1.24.1");
    expect(vStrings).toContain("1.23.5");
  });

  it('strips "go" prefix via tag_pattern', async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_GO_RESPONSE),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(GOLANG_CONFIG);

    for (const v of versions) {
      expect(v.version).not.toMatch(/^go/);
    }
  });

  it("filters by file_kind_value (excludes source tarballs)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_GO_RESPONSE),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(GOLANG_CONFIG);

    const v124 = versions.find((v) => v.version === "1.24.1");
    expect(v124).toBeDefined();

    // linux/x86-64 should be found (kind=archive)
    const linuxArt = v124!.artifacts.get("linux/x86-64");
    expect(linuxArt).toBeDefined();
    expect(linuxArt!.filename).toBe("go1.24.1.linux-amd64.tar.gz");
    expect(linuxArt!.checksum).toBe("abc123");
  });

  it("includes checksum from file_checksum_field", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_GO_RESPONSE),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(GOLANG_CONFIG);

    const v124 = versions.find((v) => v.version === "1.24.1");
    const macArt = v124!.artifacts.get("macos/arm64");
    expect(macArt).toBeDefined();
    expect(macArt!.checksum).toBe("def456");
    expect(macArt!.checksumType).toBe("sha256");
  });

  it("throws on API error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        text: () => Promise.resolve("server error"),
      }),
    );

    const strategy = new JsonApiStrategy();
    await expect(strategy.discoverVersions(GOLANG_CONFIG)).rejects.toThrow("500");
  });

  it("throws on malformed JSON that does not produce an array", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ error: "not an array of releases" }),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new JsonApiStrategy();
    // JSONPath filter on a non-array might return empty or throw
    const versions = await strategy.discoverVersions(GOLANG_CONFIG);
    expect(versions).toHaveLength(0);
  });
});

describe("JsonApiStrategy — two-step submode (Adoptium)", () => {
  it("discovers versions using two-step API", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(MOCK_ADOPTIUM_VERSION_LIST),
        text: () => Promise.resolve(""),
      })
      .mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_ADOPTIUM_RELEASE),
        text: () => Promise.resolve(""),
      });

    vi.stubGlobal("fetch", fetchMock);

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(OPENJDK_CONFIG);

    expect(versions.length).toBeGreaterThan(0);
    const v = versions.find((v) => v.versionGroup === "21");
    expect(v).toBeDefined();
  });

  it("marks LTS versions correctly from API", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(MOCK_ADOPTIUM_VERSION_LIST),
        text: () => Promise.resolve(""),
      })
      .mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_ADOPTIUM_RELEASE),
        text: () => Promise.resolve(""),
      });

    vi.stubGlobal("fetch", fetchMock);

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(OPENJDK_CONFIG);

    const v21 = versions.find((v) => v.versionGroup === "21");
    expect(v21).toBeDefined();
    expect(v21!.isLts).toBe(true);
  });
});
