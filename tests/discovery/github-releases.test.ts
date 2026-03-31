import { describe, it, expect, vi, beforeEach } from "vitest";
import { GitHubReleasesStrategy } from "../../src/discovery/github-releases.js";
import { PackageConfig } from "../../src/types/package-config.js";

const UV_CONFIG: PackageConfig = {
  name: "uv",
  display_name: "uv",
  vendor: "Astral",
  discovery: {
    type: "github-releases",
    repo: "astral-sh/uv",
    include_prereleases: false,
    tag_pattern: "^(\\d+\\.\\d+\\.\\d+)$",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 3 },
  checksum: { type: "github-asset", algorithm: "sha256", asset_suffix: ".sha256" },
  platforms: [
    {
      os: "linux",
      arch: "x86-64",
      os_upstream: "unknown-linux-gnu",
      arch_upstream: "x86_64",
      extension: "tar.gz",
      filename_template: "uv-{arch}-{os}.{ext}",
    },
    {
      os: "macos",
      arch: "arm64",
      os_upstream: "apple-darwin",
      arch_upstream: "aarch64",
      extension: "tar.gz",
      filename_template: "uv-{arch}-{os}.{ext}",
    },
  ],
};

const MOCK_RELEASES = [
  {
    tag_name: "0.6.2",
    prerelease: false,
    draft: false,
    published_at: "2024-03-15T10:00:00Z",
    assets: [
      {
        name: "uv-x86_64-unknown-linux-gnu.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/uv/releases/download/0.6.2/uv-x86_64-unknown-linux-gnu.tar.gz",
        size: 12345678,
      },
      {
        name: "uv-x86_64-unknown-linux-gnu.tar.gz.sha256",
        browser_download_url:
          "https://github.com/astral-sh/uv/releases/download/0.6.2/uv-x86_64-unknown-linux-gnu.tar.gz.sha256",
        size: 64,
      },
      {
        name: "uv-aarch64-apple-darwin.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/uv/releases/download/0.6.2/uv-aarch64-apple-darwin.tar.gz",
        size: 11223344,
      },
    ],
  },
  {
    tag_name: "0.6.1",
    prerelease: false,
    draft: false,
    published_at: "2024-03-10T08:00:00Z",
    assets: [
      {
        name: "uv-x86_64-unknown-linux-gnu.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/uv/releases/download/0.6.1/uv-x86_64-unknown-linux-gnu.tar.gz",
        size: 12000000,
      },
    ],
  },
  {
    tag_name: "0.7.0-alpha.1",
    prerelease: true,
    draft: false,
    published_at: "2024-03-20T12:00:00Z",
    assets: [],
  },
  {
    tag_name: "not-a-version",
    prerelease: false,
    draft: false,
    published_at: null,
    assets: [],
  },
];

beforeEach(() => {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(MOCK_RELEASES),
      text: () => Promise.resolve(""),
    }),
  );
});

// ── asset_version_pattern test fixtures ────────────────────────────────────

const PYTHON_CONFIG: PackageConfig = {
  name: "python",
  display_name: "Python",
  vendor: "Astral",
  discovery: {
    type: "github-releases",
    repo: "astral-sh/python-build-standalone",
    include_prereleases: false,
    asset_version_pattern: "^cpython-(3\\.(?:11|12|13)\\.\\d+)\\+",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    min_version: "3.11",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2, groups_to_keep: 3 },
  checksum: { type: "github-asset-digest", algorithm: "sha256" },
  platforms: [
    {
      os: "macos",
      arch: "arm64",
      os_upstream: "apple-darwin",
      arch_upstream: "aarch64",
      extension: "tar.gz",
      filename_template: "cpython-{version}+{tag}-{arch}-{os}-install_only.{ext}",
    },
    {
      os: "linux",
      arch: "x86-64",
      os_upstream: "unknown-linux-gnu",
      arch_upstream: "x86_64",
      extension: "tar.gz",
      filename_template: "cpython-{version}+{tag}-{arch}-{os}-install_only.{ext}",
    },
  ],
};

const PYTHON_MOCK_RELEASES = [
  {
    tag_name: "20260325",
    prerelease: false,
    draft: false,
    published_at: "2026-03-25T10:00:00Z",
    assets: [
      // Python 3.13
      {
        name: "cpython-3.13.2+20260325-aarch64-apple-darwin-install_only.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/python-build-standalone/releases/download/20260325/cpython-3.13.2+20260325-aarch64-apple-darwin-install_only.tar.gz",
        size: 50000000,
        digest: "sha256:aabbcc1111",
      },
      {
        name: "cpython-3.13.2+20260325-x86_64-unknown-linux-gnu-install_only.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/python-build-standalone/releases/download/20260325/cpython-3.13.2+20260325-x86_64-unknown-linux-gnu-install_only.tar.gz",
        size: 48000000,
        digest: "sha256:ddeeff2222",
      },
      // Python 3.12
      {
        name: "cpython-3.12.9+20260325-aarch64-apple-darwin-install_only.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/python-build-standalone/releases/download/20260325/cpython-3.12.9+20260325-aarch64-apple-darwin-install_only.tar.gz",
        size: 49000000,
        digest: "sha256:112233aabb",
      },
      {
        name: "cpython-3.12.9+20260325-x86_64-unknown-linux-gnu-install_only.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/python-build-standalone/releases/download/20260325/cpython-3.12.9+20260325-x86_64-unknown-linux-gnu-install_only.tar.gz",
        size: 47000000,
        digest: "sha256:445566ccdd",
      },
      // Python 3.11
      {
        name: "cpython-3.11.12+20260325-aarch64-apple-darwin-install_only.tar.gz",
        browser_download_url:
          "https://github.com/astral-sh/python-build-standalone/releases/download/20260325/cpython-3.11.12+20260325-aarch64-apple-darwin-install_only.tar.gz",
        size: 46000000,
        digest: "sha256:778899eeff",
      },
      // Irrelevant asset (different variant) — should not create a version
      {
        name: "cpython-3.13.2+20260325-aarch64-apple-darwin-full.tar.gz",
        browser_download_url: "https://github.com/...",
        size: 90000000,
        digest: "sha256:ffffffff",
      },
    ],
  },
];

describe("GitHubReleasesStrategy", () => {
  it("discovers versions and resolves artifact URLs", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);

    expect(versions).toHaveLength(2); // 0.6.2 and 0.6.1 (prerelease excluded)

    const v062 = versions.find((v) => v.version === "0.6.2");
    expect(v062).toBeDefined();
    expect(v062!.versionGroup).toBe("0.6");
    expect(v062!.isLts).toBe(false);

    // Check linux/x86-64 artifact
    const linuxArt = v062!.artifacts.get("linux/x86-64");
    expect(linuxArt).toBeDefined();
    expect(linuxArt!.url).toContain("uv-x86_64-unknown-linux-gnu.tar.gz");
    expect(linuxArt!.filename).toBe("uv-x86_64-unknown-linux-gnu.tar.gz");
    // checksumUrl holds the URL to fetch; checksum (hex digest) is undefined at discovery time
    expect(linuxArt!.checksumUrl).toContain(".sha256");
    expect(linuxArt!.checksum).toBeUndefined();
  });

  it("filters out prereleases when include_prereleases=false", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);

    const versionStrings = versions.map((v) => v.version);
    expect(versionStrings).not.toContain("0.7.0-alpha.1");
  });

  it("includes prereleases when include_prereleases=true", async () => {
    const configWithPre: PackageConfig = {
      ...UV_CONFIG,
      discovery: {
        ...UV_CONFIG.discovery,
        type: "github-releases",
        repo: "astral-sh/uv",
        include_prereleases: true,
        tag_pattern: "^(\\d+\\.\\d+\\.\\d+(?:-\\S+)?)$",
      },
    };

    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(configWithPre);
    const versionStrings = versions.map((v) => v.version);
    expect(versionStrings).toContain("0.7.0-alpha.1");
  });

  it("skips tags that do not match tag_pattern", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);

    const versionStrings = versions.map((v) => v.version);
    expect(versionStrings).not.toContain("not-a-version");
  });

  it("skips draft releases", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve([{ tag_name: "1.0.0", prerelease: false, draft: true, assets: [] }]),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);
    expect(versions).toHaveLength(0);
  });

  it("throws on API error response", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 403,
        text: () => Promise.resolve("rate limited"),
      }),
    );

    const strategy = new GitHubReleasesStrategy();
    await expect(strategy.discoverVersions(UV_CONFIG)).rejects.toThrow("403");
  });

  it("populates releasedAt from published_at", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);

    const v062 = versions.find((v) => v.version === "0.6.2");
    expect(v062!.releasedAt).toEqual(new Date("2024-03-15T10:00:00Z"));

    const v061 = versions.find((v) => v.version === "0.6.1");
    expect(v061!.releasedAt).toEqual(new Date("2024-03-10T08:00:00Z"));
  });

  it("assigns correct version groups", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);

    for (const v of versions) {
      expect(v.versionGroup).toMatch(/^\d+\.\d+$/);
    }
  });
});

describe("GitHubReleasesStrategy — asset_version_pattern mode", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(PYTHON_MOCK_RELEASES),
        text: () => Promise.resolve(""),
      }),
    );
  });

  it("produces one DiscoveredVersion per unique extracted version, not one per release", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(PYTHON_CONFIG);

    const versionStrings = versions.map((v) => v.version).sort();
    expect(versionStrings).toContain("3.13.2");
    expect(versionStrings).toContain("3.12.9");
    expect(versionStrings).toContain("3.11.12");
    // Should be 3 versions, not 1 release
    expect(versions).toHaveLength(3);
  });

  it("substitutes {tag} correctly in artifact URLs", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(PYTHON_CONFIG);

    const v3_13 = versions.find((v) => v.version === "3.13.2");
    expect(v3_13).toBeDefined();

    const macArt = v3_13!.artifacts.get("macos/arm64");
    expect(macArt).toBeDefined();
    expect(macArt!.filename).toBe(
      "cpython-3.13.2+20260325-aarch64-apple-darwin-install_only.tar.gz",
    );
    expect(macArt!.url).toContain("20260325");
    expect(macArt!.url).toContain("3.13.2");
  });

  it("extracts checksum from asset digest field, stripping algorithm prefix", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(PYTHON_CONFIG);

    const v3_13 = versions.find((v) => v.version === "3.13.2");
    const macArt = v3_13!.artifacts.get("macos/arm64");
    expect(macArt!.checksum).toBe("aabbcc1111");
    expect(macArt!.checksumType).toBe("sha256");
    // No checksumUrl — digest comes from the asset object itself
    expect(macArt!.checksumUrl).toBeUndefined();

    const linuxArt = v3_13!.artifacts.get("linux/x86-64");
    expect(linuxArt!.checksum).toBe("ddeeff2222");
  });

  it("assigns correct version groups", async () => {
    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(PYTHON_CONFIG);

    const groups = versions.map((v) => v.versionGroup).sort();
    expect(groups).toEqual(["3.11", "3.12", "3.13"]);
  });

  it("respects min_version — excludes versions below the threshold", async () => {
    const configWithHighMin: PackageConfig = {
      ...PYTHON_CONFIG,
      versioning: { ...PYTHON_CONFIG.versioning, min_version: "3.12" },
    };

    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(configWithHighMin);

    const versionStrings = versions.map((v) => v.version);
    expect(versionStrings).not.toContain("3.11.12");
    expect(versionStrings).toContain("3.12.9");
    expect(versionStrings).toContain("3.13.2");
  });

  it("does not affect normal tag-based mode", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(MOCK_RELEASES),
        text: () => Promise.resolve(""),
      }),
    );

    const strategy = new GitHubReleasesStrategy();
    const versions = await strategy.discoverVersions(UV_CONFIG);

    // Tag-based mode should still work as before
    expect(versions.map((v) => v.version)).toContain("0.6.2");
    expect(versions.map((v) => v.version)).toContain("0.6.1");
  });

  it("uses max_releases as per_page when set", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(PYTHON_MOCK_RELEASES),
      text: () => Promise.resolve(""),
    });
    vi.stubGlobal("fetch", mockFetch);

    const configWithMaxReleases: PackageConfig = {
      ...PYTHON_CONFIG,
      discovery: {
        ...PYTHON_CONFIG.discovery,
        type: "github-releases",
        repo: "astral-sh/python-build-standalone",
        include_prereleases: false,
        asset_version_pattern: "^cpython-(3\\.(?:11|12|13)\\.\\d+)\\+",
        max_releases: 10,
      },
    };

    const strategy = new GitHubReleasesStrategy();
    await strategy.discoverVersions(configWithMaxReleases);

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("per_page=10");
  });

  it("defaults to per_page=100 when max_releases is not set", async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve(PYTHON_MOCK_RELEASES),
      text: () => Promise.resolve(""),
    });
    vi.stubGlobal("fetch", mockFetch);

    const strategy = new GitHubReleasesStrategy();
    await strategy.discoverVersions(PYTHON_CONFIG);

    const calledUrl = mockFetch.mock.calls[0][0] as string;
    expect(calledUrl).toContain("per_page=100");
  });
});
