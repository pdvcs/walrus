import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { DirectoryListingStrategy } from "../../src/discovery/directory-listing.js";
import { PackageConfigSchema, PackageConfig } from "../../src/types/package-config.js";
import { selectRetentionWindow } from "../../src/common/retention-window.js";
import { log } from "../../src/common/log.js";

// ── Fixtures ────────────────────────────────────────────────────────────────

const LISTING_URL = "https://ftp.example.test/pub/source/";
const URL_TEMPLATE =
  "https://get.example.test/postgresql/postgresql-{version}-1-{os}-binaries.{ext}";

/** Windows and macOS only — the two platforms the PostgreSQL package serves. */
const PG_CONFIG: PackageConfig = {
  name: "postgresql",
  display_name: "PostgreSQL",
  vendor: "PostgreSQL Global Development Group / EnterpriseDB",
  discovery: {
    type: "directory-listing",
    url: LISTING_URL,
    pattern: 'href="v(\\d+\\.\\d+)/"',
  },
  versioning: {
    type: "semver",
    version_group_extract: "^(\\d+)",
    min_version: "17.0",
    lts_support: false,
    lts_source: "none",
  },
  retention: { versions_per_group: 2, groups_to_keep: 2, cooling_off_days: 3 },
  checksum: { type: "none", algorithm: "sha256" },
  platforms: [
    {
      os: "windows",
      arch: "x86-64",
      os_upstream: "windows-x64",
      arch_upstream: "x64",
      extension: "zip",
      url_template: URL_TEMPLATE,
    },
    {
      os: "macos",
      arch: "x86-64",
      os_upstream: "osx",
      arch_upstream: "x64",
      extension: "zip",
      url_template: URL_TEMPLATE,
    },
  ],
};

/** An Apache autoindex body carrying the version directories. */
function listing(versions: string[]): string {
  const links = versions
    .map((v) => `<a href="v${v}/">v${v}/</a>                2026-08-13 00:00    -`)
    .join("\n");
  return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head><title>Index of /pub/source</title></head>
<body><h1>Index of /pub/source</h1>
<pre>${links}
</pre></body></html>`;
}

const server = setupServer();

function serveListing(body: string, status = 200): void {
  server.use(http.get(LISTING_URL, () => HttpResponse.text(body, { status })));
}

beforeEach(() => {
  server.listen({ onUnhandledRequest: "error" });
});

afterEach(() => {
  server.close();
  vi.restoreAllMocks();
});

// ── Discovery ───────────────────────────────────────────────────────────────

describe("DirectoryListingStrategy", () => {
  it("extracts versions newest-first and builds each platform's URL from its template", async () => {
    serveListing(listing(["18.6", "18.4", "18.0", "17.11", "17.10", "16.15", "6.3"]));

    const versions = await new DirectoryListingStrategy().discoverVersions(PG_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["18.6", "18.4", "18.0", "17.11", "17.10"]);
    expect(versions.map((v) => v.versionGroup)).toEqual(["18", "18", "18", "17", "17"]);

    const latest = versions[0];
    expect(latest.artifacts.size).toBe(2);
    expect(latest.releasedAt).toBeUndefined();
    expect(latest.isLts).toBe(false);

    const win = latest.artifacts.get("windows/x86-64")!;
    expect(win.url).toBe(
      "https://get.example.test/postgresql/postgresql-18.6-1-windows-x64-binaries.zip",
    );
    expect(win.filename).toBe("postgresql-18.6-1-windows-x64-binaries.zip");

    const mac = latest.artifacts.get("macos/x86-64")!;
    expect(mac.url).toBe("https://get.example.test/postgresql/postgresql-18.6-1-osx-binaries.zip");
    expect(mac.filename).toBe("postgresql-18.6-1-osx-binaries.zip");
  });

  it("applies min_version before grouping", async () => {
    serveListing(listing(["18.6", "17.11", "17.0", "16.15", "15.19", "6.3"]));

    const versions = await new DirectoryListingStrategy().discoverVersions(PG_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["18.6", "17.11", "17.0"]);
  });

  it("keeps the newest 2 minors of the newest 2 majors under the package retention window", async () => {
    serveListing(listing(["18.6", "18.4", "18.0", "17.11", "17.10", "17.9", "16.15"]));

    const versions = await new DirectoryListingStrategy().discoverVersions(PG_CONFIG);
    const kept = selectRetentionWindow(versions, PG_CONFIG.retention).map((v) => v.version);

    // Steady state is 2 majors x 2 minors.
    expect(kept.sort()).toEqual(["17.10", "17.11", "18.4", "18.6"]);
  });

  it("deduplicates repeated links", async () => {
    serveListing(listing(["18.6", "18.6", "18.4"]));

    const versions = await new DirectoryListingStrategy().discoverVersions(PG_CONFIG);

    expect(versions.map((v) => v.version)).toEqual(["18.6", "18.4"]);
  });

  it("returns an empty list when the pattern matches nothing", async () => {
    const warn = vi.spyOn(log, "warn").mockImplementation(() => undefined);
    serveListing("<html><body><h1>Index of /pub/source</h1><pre>nothing here</pre></body></html>");

    const versions = await new DirectoryListingStrategy().discoverVersions(PG_CONFIG);

    expect(versions).toEqual([]);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ url: LISTING_URL }),
      expect.stringContaining("matched no versions"),
    );
  });

  it("resolves a separate-file checksum URL when configured", async () => {
    serveListing(listing(["18.6"]));
    const config: PackageConfig = {
      ...PG_CONFIG,
      checksum: {
        type: "separate-file",
        algorithm: "sha256",
        url_template: "https://get.example.test/postgresql/{version}/SHA256SUMS",
      },
    };

    const versions = await new DirectoryListingStrategy().discoverVersions(config);

    const win = versions[0].artifacts.get("windows/x86-64")!;
    expect(win.checksumUrl).toBe("https://get.example.test/postgresql/18.6/SHA256SUMS");
    expect(win.checksumType).toBe("sha256");
  });

  it("rejects when the listing request fails", async () => {
    serveListing("not found", 404);

    await expect(new DirectoryListingStrategy().discoverVersions(PG_CONFIG)).rejects.toThrow("404");
  });

  it("rejects a config of the wrong discovery type", async () => {
    const config = {
      ...PG_CONFIG,
      discovery: { type: "github-releases", repo: "postgres/postgres", include_prereleases: false },
    } as PackageConfig;

    await expect(new DirectoryListingStrategy().discoverVersions(config)).rejects.toThrow(
      /directory-listing/,
    );
  });

  it("throws when a platform has no url_template", async () => {
    serveListing(listing(["18.6"]));
    const config = {
      ...PG_CONFIG,
      platforms: [
        {
          os: "windows",
          arch: "x86-64",
          os_upstream: "windows-x64",
          arch_upstream: "x64",
          extension: "zip",
        },
      ],
    } as PackageConfig;

    await expect(new DirectoryListingStrategy().discoverVersions(config)).rejects.toThrow(
      /missing url_template/,
    );
  });
});

// ── Schema ──────────────────────────────────────────────────────────────────

describe("directory-listing schema", () => {
  const base = {
    name: "postgresql",
    display_name: "PostgreSQL",
    vendor: "PostgreSQL Global Development Group / EnterpriseDB",
    versioning: { type: "semver", version_group_extract: "^(\\d+)" },
  };

  const platform = {
    os: "windows",
    arch: "x86-64",
    os_upstream: "windows-x64",
    arch_upstream: "x64",
    extension: "zip",
    url_template: URL_TEMPLATE,
  };

  it("accepts a directory-listing config whose platforms carry url_template", () => {
    const parsed = PackageConfigSchema.parse({
      ...base,
      discovery: {
        type: "directory-listing",
        url: LISTING_URL,
        pattern: 'href="v(\\d+\\.\\d+)/"',
      },
      platforms: [platform],
    });

    expect(parsed.discovery.type).toBe("directory-listing");
  });

  it("rejects a directory-listing platform missing url_template", () => {
    expect(() =>
      PackageConfigSchema.parse({
        ...base,
        discovery: {
          type: "directory-listing",
          url: LISTING_URL,
          pattern: 'href="v(\\d+\\.\\d+)/"',
        },
        platforms: [
          {
            os: "windows",
            arch: "x86-64",
            os_upstream: "windows-x64",
            arch_upstream: "x64",
            extension: "zip",
          },
        ],
      }),
    ).toThrow(/url_template/);
  });

  it("rejects a pattern with no capture group", () => {
    expect(() =>
      PackageConfigSchema.parse({
        ...base,
        discovery: {
          type: "directory-listing",
          url: LISTING_URL,
          pattern: 'href="v\\d+\\.\\d+/"',
        },
        platforms: [platform],
      }),
    ).toThrow(/capture group/);
  });
});
