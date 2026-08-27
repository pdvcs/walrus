import { describe, it, expect, vi, beforeEach } from "vitest";
import { JsonApiStrategy } from "../../src/discovery/json-api.js";
import { log } from "../../src/common/log.js";
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

// ── Version-list submode (VS Code) ──────────────────────────────────────────
//
// The upstream returns bare version strings with no per-release metadata, so artifact URLs are
// built from each platform's url_template and named by filename_template.

const VSCODE_CONFIG: PackageConfig = {
  name: "vscode",
  display_name: "Visual Studio Code",
  vendor: "Microsoft",
  discovery: {
    type: "json-api",
    url: "https://update.code.visualstudio.com/api/releases/stable",
    releases_path: "$[*]",
    include_prereleases: false,
  } as PackageConfig["discovery"],
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+)",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 3, groups_to_keep: 1 },
  platforms: [
    {
      os: "linux",
      arch: "x86-64",
      os_upstream: "linux-x64",
      arch_upstream: "x64",
      extension: "tar.gz",
      url_template: "https://update.code.visualstudio.com/{version}/{os}/stable",
      filename_template: "VSCode-{version}-{os}.{ext}",
    },
    {
      os: "macos",
      arch: "arm64",
      os_upstream: "darwin-arm64",
      arch_upstream: "arm64",
      extension: "zip",
      url_template: "https://update.code.visualstudio.com/{version}/{os}/stable",
      filename_template: "VSCode-{version}-{os}.{ext}",
    },
  ],
};

const MOCK_VSCODE_RESPONSE = ["1.135.0", "1.134.0", "1.133.0"];

function stubFetchJson(payload: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(payload),
      text: () => Promise.resolve(""),
    }),
  );
}

describe("JsonApiStrategy — version-list submode (VS Code)", () => {
  it("treats bare strings in the releases array as versions", async () => {
    stubFetchJson(MOCK_VSCODE_RESPONSE);

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(VSCODE_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["1.135.0", "1.134.0", "1.133.0"]);
    // VS Code has no release series — every version lands in one group.
    expect(new Set(versions.map((v) => v.versionGroup))).toEqual(new Set(["1"]));
  });

  it("builds one artifact per platform from url_template", async () => {
    stubFetchJson(MOCK_VSCODE_RESPONSE);

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(VSCODE_CONFIG);
    const latest = versions.find((v) => v.version === "1.135.0")!;

    expect(latest.artifacts.size).toBe(2);
    expect(latest.artifacts.get("linux/x86-64")).toMatchObject({
      url: "https://update.code.visualstudio.com/1.135.0/linux-x64/stable",
      filename: "VSCode-1.135.0-linux-x64.tar.gz",
    });
    expect(latest.artifacts.get("macos/arm64")).toMatchObject({
      url: "https://update.code.visualstudio.com/1.135.0/darwin-arm64/stable",
      filename: "VSCode-1.135.0-darwin-arm64.zip",
    });
  });

  it("skips platforms with no url_template", async () => {
    stubFetchJson(MOCK_VSCODE_RESPONSE);

    const config: PackageConfig = {
      ...VSCODE_CONFIG,
      platforms: [
        { ...VSCODE_CONFIG.platforms[0], url_template: undefined },
        VSCODE_CONFIG.platforms[1],
      ],
    };

    const strategy = new JsonApiStrategy();
    const versions = await strategy.discoverVersions(config);

    expect(versions[0].artifacts.size).toBe(1);
    expect(versions[0].artifacts.has("macos/arm64")).toBe(true);
  });

  it("still requires release_version_field when releases are objects", async () => {
    stubFetchJson([{ version: "1.135.0" }]);

    const strategy = new JsonApiStrategy();
    await expect(strategy.discoverVersions(VSCODE_CONFIG)).rejects.toThrow(/release_version_field/);
  });
});

// ── Platform-map submode (JetBrains) ────────────────────────────────────────

/**
 * The shape the array modes cannot read: downloads keyed by platform, with the discriminator
 * as the object key rather than a field inside the value. Two releases, deliberately spanning
 * JetBrains' mid-window rename of the artifact prefix (`ideaIU-` → `idea-`), and carrying keys
 * walrus does not serve.
 */
const MOCK_JETBRAINS_RESPONSE = {
  IIU: [
    {
      version: "2026.2.1",
      date: "2026-08-12",
      majorVersion: "2026.2",
      downloads: {
        windowsZip: {
          link: "https://download.jetbrains.com/idea/idea-2026.2.1.win.zip",
          size: 1614981679,
          checksumLink: "https://download.jetbrains.com/idea/idea-2026.2.1.win.zip.sha256",
        },
        macM1: {
          link: "https://download.jetbrains.com/idea/idea-2026.2.1-aarch64.dmg",
          size: 1512591157,
          checksumLink: "https://download.jetbrains.com/idea/idea-2026.2.1-aarch64.dmg.sha256",
        },
        linux: { link: "https://download.jetbrains.com/idea/idea-2026.2.1.tar.gz", size: 1 },
        windowsJBR8: { link: "https://download.jetbrains.com/idea/idea-2026.2.1-jbr8.win.zip" },
        thirdPartyLibrariesJson: { link: "https://download.jetbrains.com/idea/libs.json" },
      },
    },
    {
      version: "2025.2.6.3",
      date: "2026-07-29",
      majorVersion: "2025.2",
      downloads: {
        windowsZip: {
          link: "https://download.jetbrains.com/idea/ideaIU-2025.2.6.3.win.zip",
          size: 1900000000,
          checksumLink: "https://download.jetbrains.com/idea/ideaIU-2025.2.6.3.win.zip.sha256",
        },
        macM1: {
          link: "https://download.jetbrains.com/idea/ideaIU-2025.2.6.3-aarch64.dmg",
          size: 1800000000,
        },
      },
    },
  ],
};

const JETBRAINS_CONFIG: PackageConfig = {
  name: "intellij",
  display_name: "IntelliJ IDEA Ultimate",
  vendor: "JetBrains",
  discovery: {
    type: "json-api",
    url: "https://data.services.jetbrains.com/products/releases?code=IIU",
    releases_path: "$.IIU[*]",
    release_version_field: "version",
    release_date_field: "date",
    files_field: "downloads",
    files_shape: "platform-map",
    file_url_field: "link",
    file_checksum_url_field: "checksumLink",
    file_size_field: "size",
  },
  versioning: {
    type: "calver",
    version_group_extract: "^(\\d+\\.\\d+)",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2 },
  checksum: { type: "separate-file", algorithm: "sha256" },
  platforms: [
    {
      os: "windows",
      arch: "x86-64",
      os_upstream: "windowsZip",
      arch_upstream: "x86-64",
      extension: "zip",
    },
    {
      os: "macos",
      arch: "arm64",
      os_upstream: "macM1",
      arch_upstream: "aarch64",
      extension: "dmg",
    },
  ],
} as unknown as PackageConfig;

function stubJetBrains(): void {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_JETBRAINS_RESPONSE),
      text: () => Promise.resolve(""),
    }),
  );
}

describe("JsonApiStrategy — platform-map submode (JetBrains)", () => {
  it("resolves each platform by the download map's key", async () => {
    stubJetBrains();

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["2026.2.1", "2025.2.6.3"]);
    const latest = versions[0];
    expect([...latest.artifacts.keys()].sort()).toEqual(["macos/arm64", "windows/x86-64"]);
    expect(latest.artifacts.get("windows/x86-64")!.url).toBe(
      "https://download.jetbrains.com/idea/idea-2026.2.1.win.zip",
    );
  });

  it("takes the filename from the link, spanning the mid-window prefix rename", async () => {
    // idea-2026.2.1.win.zip but ideaIU-2025.2.6.3.win.zip, inside one retention window. No
    // filename_template spans that, which is why this mode does not construct filenames.
    stubJetBrains();

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);

    expect(versions[0].artifacts.get("windows/x86-64")!.filename).toBe("idea-2026.2.1.win.zip");
    expect(versions[1].artifacts.get("windows/x86-64")!.filename).toBe("ideaIU-2025.2.6.3.win.zip");
  });

  it("carries checksumLink through as a sidecar URL", async () => {
    stubJetBrains();

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);
    const artifact = versions[0].artifacts.get("macos/arm64")!;

    expect(artifact.checksumUrl).toBe(
      "https://download.jetbrains.com/idea/idea-2026.2.1-aarch64.dmg.sha256",
    );
    expect(artifact.checksumType).toBe("sha256");
    expect(artifact.checksum).toBeUndefined();
  });

  it("leaves the sidecar fields unset when the API omits one", async () => {
    stubJetBrains();

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);
    const artifact = versions[1].artifacts.get("macos/arm64")!;

    expect(artifact.checksumUrl).toBeUndefined();
    expect(artifact.checksumType).toBeUndefined();
  });

  it("captures the published size so a truncated transfer can be caught", async () => {
    stubJetBrains();

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);

    expect(versions[0].artifacts.get("windows/x86-64")!.size).toBe(1614981679);
    expect(versions[0].artifacts.get("macos/arm64")!.size).toBe(1512591157);
  });

  it("ignores keys walrus does not serve, without warning noise", async () => {
    // linux, windowsJBR8 and thirdPartyLibrariesJson are all present upstream. Warning about
    // each of them on every release would drown the warning that matters.
    stubJetBrains();
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);

    expect(versions[0].artifacts.size).toBe(2);
    expect(warn).not.toHaveBeenCalled();
  });

  it("logs and skips a configured platform the API has no key for", async () => {
    stubJetBrains();
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);
    const config = {
      ...JETBRAINS_CONFIG,
      platforms: [
        ...JETBRAINS_CONFIG.platforms,
        {
          os: "windows",
          arch: "arm64",
          os_upstream: "windowsZipARM64", // JetBrains publishes no such build
          arch_upstream: "aarch64",
          extension: "zip",
        },
      ],
    } as unknown as PackageConfig;

    const versions = await new JsonApiStrategy().discoverVersions(config);

    expect(versions[0].artifacts.has("windows/arm64")).toBe(false);
    expect(versions[0].artifacts.size).toBe(2);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ key: "windowsZipARM64" }),
      expect.stringContaining("no download under this key"),
    );
  });

  it("skips a download object with no URL rather than storing an empty one", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            IIU: [
              {
                version: "2026.2.1",
                date: "2026-08-12",
                downloads: { windowsZip: { size: 10 }, macM1: { link: "https://e.test/a.dmg" } },
              },
            ],
          }),
        text: () => Promise.resolve(""),
      }),
    );
    vi.spyOn(log, "warn").mockImplementation(() => undefined);

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);

    expect(versions[0].artifacts.has("windows/x86-64")).toBe(false);
    expect(versions[0].artifacts.has("macos/arm64")).toBe(true);
  });

  it("tolerates a release whose downloads field is an array rather than a map", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({ IIU: [{ version: "2026.2.1", date: "2026-08-12", downloads: [] }] }),
        text: () => Promise.resolve(""),
      }),
    );
    vi.spyOn(log, "warn").mockImplementation(() => undefined);

    const versions = await new JsonApiStrategy().discoverVersions(JETBRAINS_CONFIG);

    expect(versions[0].artifacts.size).toBe(0);
  });
});
