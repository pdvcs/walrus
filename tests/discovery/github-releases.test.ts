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

// The artifact-resolution pre-filter has to keep everything the sync service's retention window
// keeps. When it trimmed to versions_per_group while the window also retained embargoed versions,
// the extra servable version reached the database with an empty artifact map — a version row that
// could never be downloaded or retried.
describe("GitHubReleasesStrategy — pre-filter agrees with the retention window", () => {
  const EMBARGO_CONFIG: PackageConfig = {
    ...PYTHON_CONFIG,
    retention: { versions_per_group: 2, cooling_off_days: 3 },
  };

  function release(tag: string, version: string, publishedAt: Date) {
    const filename = `cpython-${version}+${tag}-x86_64-unknown-linux-gnu-install_only.tar.gz`;
    return {
      tag_name: tag,
      prerelease: false,
      draft: false,
      published_at: publishedAt.toISOString(),
      assets: [
        {
          name: filename,
          browser_download_url: `https://example.test/${tag}/${filename}`,
          size: 48000000,
          digest: "sha256:abc123",
        },
      ],
    };
  }

  const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000);

  // Newest-first, as the GitHub API returns them. 3.13.15 is 1 day old, so still cooling off.
  const RELEASES = [
    release("20260807", "3.13.15", daysAgo(1)),
    release("20260804", "3.13.14", daysAgo(30)),
    release("20260603", "3.13.13", daysAgo(60)),
  ];

  function stubReleases() {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(RELEASES),
        text: () => Promise.resolve(""),
      }),
    );
  }

  it("resolves artifacts for the servable version an embargoed release would have displaced", async () => {
    stubReleases();
    const versions = await new GitHubReleasesStrategy().discoverVersions(EMBARGO_CONFIG);

    const bySize = new Map(versions.map((v) => [v.version, v.artifacts.size]));
    expect(bySize.get("3.13.15")).toBe(1); // embargoed — kept on top of the quota
    expect(bySize.get("3.13.14")).toBe(1);
    expect(bySize.get("3.13.13")).toBe(1); // the fallback that used to arrive empty
  });

  it("still skips resolution beyond the quota when nothing is cooling off", async () => {
    stubReleases();
    const versions = await new GitHubReleasesStrategy().discoverVersions({
      ...EMBARGO_CONFIG,
      retention: { versions_per_group: 2 },
    });

    const bySize = new Map(versions.map((v) => [v.version, v.artifacts.size]));
    expect(bySize.get("3.13.15")).toBe(1);
    expect(bySize.get("3.13.14")).toBe(1);
    expect(bySize.get("3.13.13")).toBe(0);
  });

  it("historical mode resolves every targeted candidate on a requested page", async () => {
    stubReleases();
    const versions = await new GitHubReleasesStrategy().discoverVersions(EMBARGO_CONFIG, {
      releasePage: 2,
      maxReleases: 20,
      versionGroups: ["3.13"],
      historical: true,
    });

    expect(versions).toHaveLength(3);
    expect(versions.every((version) => version.versionGroup === "3.13")).toBe(true);
    expect(versions.every((version) => version.artifacts.size === 1)).toBe(true);
    const calledUrl = (vi.mocked(fetch).mock.calls[0]?.[0] ?? "") as string;
    expect(calledUrl).toContain("per_page=20");
    expect(calledUrl).toContain("page=2");
  });
});

// python-build-standalone re-ships every maintained line in every dated release, so the newest
// release containing a version says nothing about when that version came out. Dating a version by
// the latest rebuild made months-old patches look brand new, and — because rebuilds land more
// often than a 3-day embargo elapses — kept those lines permanently in cooling-off.
describe("GitHubReleasesStrategy — asset_version_pattern release dating", () => {
  function release(tag: string, versions: string[], publishedAt: Date) {
    return {
      tag_name: tag,
      prerelease: false,
      draft: false,
      published_at: publishedAt.toISOString(),
      assets: versions.map((v) => {
        const name = `cpython-${v}+${tag}-x86_64-unknown-linux-gnu-install_only.tar.gz`;
        return {
          name,
          browser_download_url: `https://example.test/${tag}/${name}`,
          size: 48000000,
          digest: "sha256:abc123",
        };
      }),
    };
  }

  const daysAgo = (n: number) => new Date(Date.now() - n * 86_400_000);

  // 3.11.15 rides along in all three releases; 3.13.15 is genuinely new in the latest one.
  const RELEASES = [
    release("20260807", ["3.11.15", "3.13.15"], daysAgo(1)),
    release("20260804", ["3.11.15", "3.13.14"], daysAgo(30)),
    release("20260603", ["3.11.15", "3.13.13"], daysAgo(90)),
  ];

  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(RELEASES),
        text: () => Promise.resolve(""),
      }),
    );
  });

  it("dates a rebuilt version by its first appearance, not the latest release carrying it", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(PYTHON_CONFIG);

    const v = versions.find((x) => x.version === "3.11.15");
    expect(v?.releasedAt?.toISOString()).toBe(RELEASES[2].published_at);
  });

  it("still dates a genuinely new version by the release that introduced it", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(PYTHON_CONFIG);

    const v = versions.find((x) => x.version === "3.13.15");
    expect(v?.releasedAt?.toISOString()).toBe(RELEASES[0].published_at);
  });

  it("still builds artifact URLs from the newest release carrying the version", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(PYTHON_CONFIG);

    const art = versions.find((x) => x.version === "3.11.15")?.artifacts.get("linux/x86-64");
    expect(art?.filename).toBe(
      "cpython-3.11.15+20260807-x86_64-unknown-linux-gnu-install_only.tar.gz",
    );
  });
});

// ── gitwindows (WAL-60): tag and asset version disagree ─────────────────────
//
// git-for-windows/git tags releases v2.55.0.windows.5 but names the assets
// Git-2.55.0.5-64-bit.tar.bz2, and the first build of a Windows series carries a
// three-component version (Git-2.54.0-...). The config therefore pivots on the asset
// filename; these tests pin the shapes the shipped packages/walrus-gitwindows.toml relies
// on, including that .windows.N rebuilds stay distinct versions.

const GITWINDOWS_CONFIG: PackageConfig = {
  name: "gitwindows",
  display_name: "Git for Windows",
  vendor: "Git for Windows project",
  discovery: {
    type: "github-releases",
    repo: "git-for-windows/git",
    include_prereleases: false,
    asset_version_pattern: "^Git-(\\d+(?:\\.\\d+)+)-(64-bit|arm64)\\.tar\\.bz2$",
    max_releases: 10,
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2, groups_to_keep: 2 },
  checksum: { type: "github-asset-digest", algorithm: "sha256" },
  platforms: [
    {
      os: "windows",
      arch: "x86-64",
      os_upstream: "windows",
      arch_upstream: "x64",
      extension: "tar.bz2",
      filename_template: "Git-{version}-64-bit.tar.bz2",
    },
    {
      os: "windows",
      arch: "arm64",
      os_upstream: "windows",
      arch_upstream: "arm64",
      extension: "tar.bz2",
      filename_template: "Git-{version}-arm64.tar.bz2",
    },
  ],
};

function gitwindowsAsset(name: string, digest: string) {
  return {
    name,
    browser_download_url: `https://github.com/git-for-windows/git/releases/download/placeholder/${name}`,
    size: 117482532,
    digest: `sha256:${digest}`,
  };
}

const GITWINDOWS_MOCK_RELEASES = [
  {
    tag_name: "v2.55.0.windows.5",
    prerelease: false,
    draft: false,
    published_at: "2026-08-20T16:21:31Z",
    assets: [
      gitwindowsAsset("Git-2.55.0.5-64-bit.tar.bz2", "x8664d1"),
      gitwindowsAsset("Git-2.55.0.5-arm64.tar.bz2", "arm64d1"),
      // Noise from the same release: nothing but the tar.bz2 assets may match.
      gitwindowsAsset("PortableGit-2.55.0.5-64-bit.7z.exe", "noise01"),
      gitwindowsAsset("MinGit-2.55.0.5-64-bit.zip", "noise02"),
      gitwindowsAsset("Git-2.55.0.5-64-bit.exe", "noise03"),
    ],
  },
  {
    tag_name: "v2.55.0.windows.4",
    prerelease: false,
    draft: false,
    published_at: "2026-08-11T17:35:02Z",
    assets: [
      gitwindowsAsset("Git-2.55.0.4-64-bit.tar.bz2", "x8664d2"),
      gitwindowsAsset("Git-2.55.0.4-arm64.tar.bz2", "arm64d2"),
    ],
  },
  {
    tag_name: "v2.54.0.windows.1",
    prerelease: false,
    draft: false,
    published_at: "2026-04-20T18:22:08Z",
    assets: [
      // First build of a Windows series: three-component version in the asset name.
      gitwindowsAsset("Git-2.54.0-64-bit.tar.bz2", "x8664d3"),
      gitwindowsAsset("Git-2.54.0-arm64.tar.bz2", "arm64d3"),
    ],
  },
  {
    // Prerelease: its assets would match no digit-only version anyway; include_prereleases
    // = false is the second gate.
    tag_name: "v2.55.0-rc2.windows.1",
    prerelease: true,
    draft: false,
    published_at: "2026-06-24T11:21:34Z",
    assets: [gitwindowsAsset("Git-2.55.0-rc2-64-bit.tar.bz2", "rcnoise")],
  },
];

describe("GitHubReleasesStrategy — gitwindows (WAL-60)", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(GITWINDOWS_MOCK_RELEASES),
        text: () => Promise.resolve(""),
      }),
    );
  });

  it("extracts the version from the asset name, not the tag", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(GITWINDOWS_CONFIG);
    const strings = versions.map((v) => v.version);
    expect(strings).toContain("2.55.0.5");
    expect(strings).toContain("2.55.0.4");
    expect(strings).toContain("2.54.0");
    for (const v of versions) expect(v.version).not.toMatch(/^v2\.55\.0\.windows/);
  });

  it("keeps .windows.N revisions of one Git version distinct", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(GITWINDOWS_CONFIG);
    const strings = versions.map((v) => v.version);
    expect(strings).toContain("2.55.0.5");
    expect(strings).toContain("2.55.0.4");
    expect(new Set(strings).size).toBe(strings.length);
  });

  it("resolves both arches for the current release and for prior releases", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(GITWINDOWS_CONFIG);

    const newest = versions.find((v) => v.version === "2.55.0.5")!;
    expect(newest.artifacts.get("windows/x86-64")!.filename).toBe("Git-2.55.0.5-64-bit.tar.bz2");
    expect(newest.artifacts.get("windows/arm64")!.filename).toBe("Git-2.55.0.5-arm64.tar.bz2");

    const prior = versions.find((v) => v.version === "2.54.0")!;
    expect(prior.artifacts.get("windows/x86-64")!.filename).toBe("Git-2.54.0-64-bit.tar.bz2");
    expect(prior.artifacts.get("windows/arm64")!.filename).toBe("Git-2.54.0-arm64.tar.bz2");
  });

  it("carries the upstream asset digest as the source checksum", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(GITWINDOWS_CONFIG);
    const art = versions.find((v) => v.version === "2.55.0.5")!.artifacts.get("windows/x86-64")!;
    expect(art.checksum).toBe("x8664d1");
    expect(art.checksumType).toBe("sha256");
    expect(art.size).toBe(117482532);
  });

  it("groups by the underlying Git minor and keeps the retention window real", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(GITWINDOWS_CONFIG);

    expect(versions.find((v) => v.version === "2.55.0.5")!.versionGroup).toBe("2.55");
    expect(versions.find((v) => v.version === "2.54.0")!.versionGroup).toBe("2.54");

    // versions_per_group = 2, groups_to_keep = 2: the two newest 2.55 rebuilds plus the
    // whole 2.54 group survive — real history for retention to act on.
    const retained = versions.filter((v) => v.artifacts.size > 0).map((v) => v.version);
    expect(retained).toEqual(["2.55.0.5", "2.55.0.4", "2.54.0"]);
  });

  it("ignores prerelease and non-matching assets", async () => {
    const versions = await new GitHubReleasesStrategy().discoverVersions(GITWINDOWS_CONFIG);
    const strings = versions.map((v) => v.version);
    expect(strings).not.toContain("2.55.0-rc2");
    for (const v of versions) {
      for (const art of v.artifacts.values()) {
        expect(art.filename).toMatch(/\.tar\.bz2$/);
        expect(art.filename).not.toMatch(/MinGit|PortableGit|\.exe$/);
      }
    }
  });
});
