import { describe, it, expect, vi, beforeAll, afterEach, afterAll } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { DotnetReleasesStrategy } from "../../src/discovery/dotnet-releases.js";
import { PackageConfigSchema, PackageConfig } from "../../src/types/package-config.js";
import { log } from "../../src/common/log.js";
import { selectRetentionWindow } from "../../src/common/retention-window.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

const URL = "https://raw.githubusercontent.com/dotnet/core/main/release-notes/10.0/releases.json";
const URL_8 = "https://raw.githubusercontent.com/dotnet/core/main/release-notes/8.0/releases.json";

const WINDOWS_SDK: PackageConfig["platforms"] = [
  {
    os: "windows",
    arch: "x86-64",
    os_upstream: "win-x64",
    arch_upstream: "x64",
    extension: "zip",
  },
];

const SDK_CONFIG: PackageConfig = {
  name: "dotnetsdk",
  display_name: ".NET SDK",
  vendor: "Microsoft",
  discovery: {
    type: "dotnet-releases",
    url: URL,
    component: "sdk",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+\\.\\d)",
    min_version: "10.0",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 1, groups_to_keep: 2 },
  platforms: WINDOWS_SDK,
};

const HOSTING_CONFIG: PackageConfig = {
  name: "asp-hosting",
  display_name: "ASP.NET Core Hosting Bundle",
  vendor: "Microsoft",
  discovery: {
    type: "dotnet-releases",
    url: URL,
    component: "aspnetcore-runtime",
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    min_version: "10.0",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2, groups_to_keep: 1 },
  platforms: [
    {
      os: "windows",
      arch: "x86-64",
      os_upstream: "",
      arch_upstream: "x64",
      extension: "exe",
      name_must_contain: "hosting",
    },
  ],
};

/** The real shape: two channels fetched together, one group kept per channel. */
const MULTI_CHANNEL_HOSTING_CONFIG: PackageConfig = {
  ...HOSTING_CONFIG,
  discovery: { type: "dotnet-releases", url: [URL, URL_8], component: "aspnetcore-runtime" },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+\\.\\d+)",
    min_version: "8.0",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2, groups_to_keep: 2 },
};

function sdkFiles(version: string): unknown[] {
  return [
    {
      name: "dotnet-sdk-win-x64.exe",
      rid: "win-x64",
      url: `https://example.test/Sdk/${version}/dotnet-sdk-${version}-win-x64.exe`,
      hash: `exe-${version}`,
    },
    {
      name: "dotnet-sdk-win-x64.zip",
      rid: "win-x64",
      url: `https://example.test/Sdk/${version}/dotnet-sdk-${version}-win-x64.zip`,
      hash: `zip-${version}`,
    },
    {
      name: "dotnet-sdk-osx-arm64.pkg",
      rid: "osx-arm64",
      url: `https://example.test/Sdk/${version}/dotnet-sdk-${version}-osx-arm64.pkg`,
      hash: `pkg-${version}`,
    },
    {
      name: "dotnet-sdk-osx-arm64.tar.gz",
      rid: "osx-arm64",
      url: `https://example.test/Sdk/${version}/dotnet-sdk-${version}-osx-arm64.tar.gz`,
      hash: `osx-${version}`,
    },
    {
      name: "dotnet-sdk-linux-x64.tar.gz",
      rid: "linux-x64",
      url: `https://example.test/Sdk/${version}/dotnet-sdk-${version}-linux-x64.tar.gz`,
      hash: `linux-${version}`,
    },
    {
      name: "dotnet-sdk-linux-arm.tar.gz",
      rid: "linux-arm",
      url: `https://example.test/Sdk/${version}/dotnet-sdk-${version}-linux-arm.tar.gz`,
      hash: `linuxarm-${version}`,
    },
  ];
}

function sdkEntry(version: string, runtimeVersion: string): Record<string, unknown> {
  return {
    version,
    "runtime-version": runtimeVersion,
    files: sdkFiles(version),
  };
}

function hostingFiles(version: string): unknown[] {
  return [
    {
      name: "aspnetcore-runtime-linux-x64.tar.gz",
      rid: "linux-x64",
      url: `https://example.test/aspnetcore/Runtime/${version}/aspnetcore-runtime-${version}-linux-x64.tar.gz`,
      hash: `linux-${version}`,
    },
    {
      name: "dotnet-hosting-win.exe",
      rid: "",
      url: `https://example.test/aspnetcore/Runtime/${version}/dotnet-hosting-${version}-win.exe`,
      hash: `hosting-${version}`,
    },
  ];
}

function release(
  date: string,
  sdk: Record<string, unknown>,
  sdks: Record<string, unknown>[],
  aspnetVersion: string,
): Record<string, unknown> {
  return {
    "release-date": date,
    sdk,
    sdks,
    "aspnetcore-runtime": {
      version: aspnetVersion,
      files: hostingFiles(aspnetVersion),
    },
  };
}

/** Three releases spanning the two newest SDK feature bands (4xx and 3xx) plus the 1xx band. */
const DOCUMENT = {
  releases: [
    release(
      "2026-09-08",
      sdkEntry("10.0.401", "10.0.12"),
      [sdkEntry("10.0.401", "10.0.12"), sdkEntry("10.0.112", "10.0.12")],
      "10.0.12",
    ),
    release(
      "2026-08-11",
      sdkEntry("10.0.400", "10.0.11"),
      [sdkEntry("10.0.400", "10.0.11"), sdkEntry("10.0.303", "10.0.11")],
      "10.0.11",
    ),
    release(
      "2026-07-14",
      sdkEntry("10.0.302", "10.0.10"),
      [sdkEntry("10.0.302", "10.0.10"), sdkEntry("10.0.110", "10.0.10")],
      "10.0.10",
    ),
  ],
};

const DOCUMENT_8 = {
  releases: [
    release("2026-09-08", sdkEntry("8.0.410", "8.0.31"), [sdkEntry("8.0.410", "8.0.31")], "8.0.31"),
    release("2026-08-11", sdkEntry("8.0.409", "8.0.30"), [sdkEntry("8.0.409", "8.0.30")], "8.0.30"),
  ],
};

const server = setupServer();

function useDocument(): void {
  server.use(http.get(URL, () => HttpResponse.json(DOCUMENT)));
}

function useTwoChannels(): void {
  server.use(
    http.get(URL, () => HttpResponse.json(DOCUMENT)),
    http.get(URL_8, () => HttpResponse.json(DOCUMENT_8)),
  );
}
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

afterEach(() => {
  server.resetHandlers();
  vi.restoreAllMocks();
});

afterAll(() => server.close());

// ── Discovery ───────────────────────────────────────────────────────────────

describe("DotnetReleasesStrategy", () => {
  it("flattens sdks[] into versions with feature-band groups and runtime cveVersion", async () => {
    useDocument();

    const versions = await new DotnetReleasesStrategy().discoverVersions(SDK_CONFIG);

    expect(versions.map((v) => v.version)).toEqual([
      "10.0.401",
      "10.0.400",
      "10.0.303",
      "10.0.302",
      "10.0.112",
      "10.0.110",
    ]);
    expect(versions.map((v) => v.versionGroup)).toEqual([
      "10.0.4",
      "10.0.4",
      "10.0.3",
      "10.0.3",
      "10.0.1",
      "10.0.1",
    ]);

    const latest = versions[0];
    expect(latest.cveVersion).toBe("10.0.12");
    expect(latest.releasedAt).toEqual(new Date("2026-09-08"));
    expect(versions.find((v) => v.version === "10.0.303")!.cveVersion).toBe("10.0.11");
  });

  it("selects the binary zip by rid and extension, excluding the installer", async () => {
    useDocument();

    const versions = await new DotnetReleasesStrategy().discoverVersions(SDK_CONFIG);
    const artifact = versions[0].artifacts.get("windows/x86-64")!;

    expect(artifact.filename).toBe("dotnet-sdk-10.0.401-win-x64.zip");
    expect(artifact.url).toBe("https://example.test/Sdk/10.0.401/dotnet-sdk-10.0.401-win-x64.zip");
    expect(artifact.checksum).toBe("zip-10.0.401");
    expect(artifact.checksumType).toBe("sha512");
  });

  it("uses the versioned URL tail as the served filename even though name omits it", async () => {
    useDocument();

    const versions = await new DotnetReleasesStrategy().discoverVersions(SDK_CONFIG);

    expect(versions[0].artifacts.get("windows/x86-64")!.filename).toContain("10.0.401");
  });

  it("selects .tar.gz over .pkg on macOS and excludes the installer", async () => {
    useDocument();
    const config: PackageConfig = {
      ...SDK_CONFIG,
      platforms: [
        {
          os: "macos",
          arch: "arm64",
          os_upstream: "osx-arm64",
          arch_upstream: "arm64",
          extension: "tar.gz",
        },
      ],
    };

    const versions = await new DotnetReleasesStrategy().discoverVersions(config);
    const artifact = versions[0].artifacts.get("macos/arm64")!;

    expect(artifact.filename).toBe("dotnet-sdk-10.0.401-osx-arm64.tar.gz");
    expect(artifact.url.endsWith(".tar.gz")).toBe(true);
  });

  it("retention keeps the newest release of each of the two newest feature bands", async () => {
    useDocument();

    const versions = await new DotnetReleasesStrategy().discoverVersions(SDK_CONFIG);
    const kept = selectRetentionWindow(versions, SDK_CONFIG.retention);

    expect(kept.map((v) => v.version)).toEqual(["10.0.401", "10.0.303"]);
  });

  it("skips a platform whose file is missing, logging rather than failing", async () => {
    useDocument();
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);
    const config: PackageConfig = {
      ...SDK_CONFIG,
      platforms: [
        ...SDK_CONFIG.platforms,
        {
          os: "linux",
          arch: "x86-64",
          os_upstream: "linux-musl-x64",
          arch_upstream: "x64",
          extension: "tar.gz",
        },
      ],
    };

    const versions = await new DotnetReleasesStrategy().discoverVersions(config);

    expect(versions[0].artifacts.has("windows/x86-64")).toBe(true);
    expect(versions[0].artifacts.has("linux/x86-64")).toBe(false);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ rid: "linux-musl-x64" }),
      expect.stringContaining("no matching file"),
    );
  });

  it("discovers the ASP.NET Core hosting bundle from the rid-less .exe", async () => {
    useDocument();

    const versions = await new DotnetReleasesStrategy().discoverVersions(HOSTING_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["10.0.12", "10.0.11", "10.0.10"]);
    expect(versions[0].cveVersion).toBeUndefined();
    expect(versions[0].versionGroup).toBe("10.0");

    const artifact = versions[0].artifacts.get("windows/x86-64")!;
    expect(artifact.filename).toBe("dotnet-hosting-10.0.12-win.exe");
    expect(artifact.checksum).toBe("hosting-10.0.12");
    expect(artifact.checksumType).toBe("sha512");

    const kept = selectRetentionWindow(versions, HOSTING_CONFIG.retention);
    expect(kept.map((v) => v.version)).toEqual(["10.0.12", "10.0.11"]);
  });

  it("merges multiple channel documents and keeps one group per channel", async () => {
    useTwoChannels();

    const versions = await new DotnetReleasesStrategy().discoverVersions(
      MULTI_CHANNEL_HOSTING_CONFIG,
    );

    expect(versions.map((v) => v.version)).toEqual([
      "10.0.12",
      "10.0.11",
      "10.0.10",
      "8.0.31",
      "8.0.30",
    ]);
    expect(versions[versions.length - 1].artifacts.get("windows/x86-64")!.filename).toBe(
      "dotnet-hosting-8.0.30-win.exe",
    );

    const kept = selectRetentionWindow(versions, MULTI_CHANNEL_HOSTING_CONFIG.retention);
    expect(kept.map((v) => v.version)).toEqual(["10.0.12", "10.0.11", "8.0.31", "8.0.30"]);
  });

  it("rejects when the channel document request fails", async () => {
    server.use(http.get(URL, () => new HttpResponse(null, { status: 404 })));

    await expect(new DotnetReleasesStrategy().discoverVersions(SDK_CONFIG)).rejects.toThrow("404");
  });

  it("rejects a config of the wrong discovery type", async () => {
    const config = {
      ...SDK_CONFIG,
      discovery: { type: "github-releases", repo: "dotnet/sdk", include_prereleases: false },
    } as PackageConfig;

    await expect(new DotnetReleasesStrategy().discoverVersions(config)).rejects.toThrow(
      /dotnet-releases/,
    );
  });
});

// ── Schema ──────────────────────────────────────────────────────────────────

describe("dotnet-releases schema", () => {
  it("accepts the config shape and the component enum", () => {
    const parsed = PackageConfigSchema.parse({
      name: "dotnetsdk",
      display_name: ".NET SDK",
      vendor: "Microsoft",
      discovery: { type: "dotnet-releases", url: URL, component: "sdk" },
      versioning: { type: "semver", version_group_extract: "^(\\d+\\.\\d+\\.\\d)" },
      platforms: [WINDOWS_SDK[0]],
    });

    expect(parsed.discovery.type).toBe("dotnet-releases");
    if (parsed.discovery.type === "dotnet-releases") {
      expect(parsed.discovery.component).toBe("sdk");
    }
  });

  it("accepts a list of channel URLs for multi-channel packages", () => {
    const parsed = PackageConfigSchema.parse({
      name: "asp-hosting",
      display_name: "ASP.NET Core Hosting Bundle",
      vendor: "Microsoft",
      discovery: { type: "dotnet-releases", url: [URL, URL_8], component: "aspnetcore-runtime" },
      versioning: { type: "semver", version_group_extract: "^(\\d+\\.\\d+)" },
      platforms: [WINDOWS_SDK[0]],
    });

    expect(parsed.discovery.type).toBe("dotnet-releases");
    if (parsed.discovery.type === "dotnet-releases") {
      expect(parsed.discovery.url).toEqual([URL, URL_8]);
    }
  });

  it("rejects an unknown component", () => {
    expect(() =>
      PackageConfigSchema.parse({
        name: "dotnetsdk",
        display_name: ".NET SDK",
        vendor: "Microsoft",
        discovery: { type: "dotnet-releases", url: URL, component: "windowsdesktop" },
        versioning: { type: "semver", version_group_extract: "^(\\d+\\.\\d+\\.\\d)" },
        platforms: [WINDOWS_SDK[0]],
      }),
    ).toThrow();
  });
});
