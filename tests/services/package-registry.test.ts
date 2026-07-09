import { describe, it, expect, beforeAll, afterAll } from "vitest";
import fs from "fs";
import path from "path";
import os from "os";
import { loadPackageConfig, loadAllPackages } from "../../src/services/package-registry.js";
import { computeVulnInput } from "../../src/services/vuln-config.js";

const FIXTURES_DIR = path.join(os.tmpdir(), "walrus-test-packages");

const VALID_UV_TOML = `
name = "uv"
display_name = "uv"
vendor = "Astral"
website = "https://github.com/astral-sh/uv"
description = "Fast Python package installer"

[discovery]
type = "github-releases"
repo = "astral-sh/uv"
include_prereleases = false
tag_pattern = "^(\\\\d+\\\\.\\\\d+\\\\.\\\\d+)$"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+\\\\.\\\\d+)"
lts_support = false

[retention]
versions_per_group = 3

[checksum]
type = "github-asset"
algorithm = "sha256"
asset_suffix = ".sha256"

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "unknown-linux-gnu"
arch_upstream = "x86_64"
extension = "tar.gz"
filename_template = "uv-{arch}-{os}.{ext}"
`;

const VALID_GOLANG_TOML = `
name = "golang"
display_name = "Go"
vendor = "Google"

[discovery]
type = "json-api"
url = "https://go.dev/dl/?mode=json&include=all"
releases_path = "$[?(@.stable==true)]"
release_version_field = "version"
tag_pattern = "^go(\\\\d+.*)"
files_field = "files"
file_os_field = "os"
file_arch_field = "arch"
file_kind_field = "kind"
file_kind_value = "archive"
file_filename_field = "filename"
file_url_base = "https://dl.google.com/go/"
file_checksum_field = "sha256"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+\\\\.\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "amd64"
extension = "tar.gz"
`;

beforeAll(() => {
  fs.mkdirSync(FIXTURES_DIR, { recursive: true });
});

afterAll(() => {
  fs.rmSync(FIXTURES_DIR, { recursive: true, force: true });
});

describe("loadPackageConfig", () => {
  it("loads and validates a valid github-releases config", () => {
    const filePath = path.join(FIXTURES_DIR, "uv-test.toml");
    fs.writeFileSync(filePath, VALID_UV_TOML);

    const config = loadPackageConfig(filePath);
    expect(config.name).toBe("uv");
    expect(config.display_name).toBe("uv");
    expect(config.vendor).toBe("Astral");
    expect(config.discovery.type).toBe("github-releases");
    expect(config.platforms).toHaveLength(1);
    expect(config.platforms[0].os).toBe("linux");
    expect(config.retention.versions_per_group).toBe(3);
  });

  it("loads and validates a valid json-api inline config", () => {
    const filePath = path.join(FIXTURES_DIR, "golang-test.toml");
    fs.writeFileSync(filePath, VALID_GOLANG_TOML);

    const config = loadPackageConfig(filePath);
    expect(config.name).toBe("golang");
    expect(config.discovery.type).toBe("json-api");
    if (config.discovery.type === "json-api") {
      expect(config.discovery.releases_path).toBe("$[?(@.stable==true)]");
      expect(config.discovery.file_checksum_field).toBe("sha256");
    }
  });

  it("throws on missing required fields", () => {
    const filePath = path.join(FIXTURES_DIR, "bad-missing.toml");
    fs.writeFileSync(
      filePath,
      `
name = "bad"
display_name = "Bad"
# missing vendor, discovery, versioning, platforms
`,
    );

    expect(() => loadPackageConfig(filePath)).toThrow(/Invalid package config/);
  });

  it("throws on invalid discovery type", () => {
    const filePath = path.join(FIXTURES_DIR, "bad-type.toml");
    fs.writeFileSync(
      filePath,
      `
name = "bad"
display_name = "Bad"
vendor = "Someone"

[discovery]
type = "unknown-strategy"
url = "https://example.com"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "amd64"
extension = "tar.gz"
`,
    );
    expect(() => loadPackageConfig(filePath)).toThrow(/Invalid package config/);
  });

  it("throws on invalid name format", () => {
    const filePath = path.join(FIXTURES_DIR, "bad-name.toml");
    fs.writeFileSync(
      filePath,
      `
name = "Bad Package!"
display_name = "Bad"
vendor = "Someone"

[discovery]
type = "github-releases"
repo = "foo/bar"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "amd64"
extension = "tar.gz"
`,
    );
    expect(() => loadPackageConfig(filePath)).toThrow(/Invalid package config/);
  });

  it("applies defaults for optional fields", () => {
    const filePath = path.join(FIXTURES_DIR, "defaults-test.toml");
    fs.writeFileSync(
      filePath,
      `
name = "test"
display_name = "Test"
vendor = "Test Co"

[discovery]
type = "github-releases"
repo = "test/test"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "amd64"
extension = "tar.gz"
`,
    );
    const config = loadPackageConfig(filePath);
    expect(config.retention.versions_per_group).toBe(3);
    expect(config.versioning.lts_source).toBe("none");
    if (config.discovery.type === "github-releases") {
      expect(config.discovery.include_prereleases).toBe(false);
    }
  });
});

describe("[vulnerabilities] section", () => {
  const withVuln = (section: string) => `
name = "openjdk"
display_name = "Eclipse Temurin OpenJDK"
vendor = "Eclipse Foundation"

[discovery]
type = "github-releases"
repo = "adoptium/temurin"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "amd64"
extension = "tar.gz"

${section}
`;

  it("parses cpes, osv, and aliases", () => {
    const filePath = path.join(FIXTURES_DIR, "vuln-ok.toml");
    fs.writeFileSync(
      filePath,
      withVuln(`[vulnerabilities]
cpes = ["eclipse:temurin", "oracle:openjdk"]
osv = { ecosystem = "Bitnami", name = "openjdk" }
aliases = ["temurin", "openjdk", "jdk"]`),
    );
    const config = loadPackageConfig(filePath);
    expect(config.vulnerabilities?.cpes).toEqual(["eclipse:temurin", "oracle:openjdk"]);
    expect(config.vulnerabilities?.osv).toEqual({ ecosystem: "Bitnami", name: "openjdk" });
    expect(config.vulnerabilities?.aliases).toContain("temurin");
  });

  it("rejects a cpe without a colon", () => {
    const filePath = path.join(FIXTURES_DIR, "vuln-bad-cpe.toml");
    fs.writeFileSync(filePath, withVuln(`[vulnerabilities]\ncpes = ["oracleopenjdk"]`));
    expect(() => loadPackageConfig(filePath)).toThrow(/Invalid package config/);
  });

  it("rejects a cpe with more than one colon", () => {
    const filePath = path.join(FIXTURES_DIR, "vuln-bad-cpe2.toml");
    fs.writeFileSync(filePath, withVuln(`[vulnerabilities]\ncpes = ["a:b:c"]`));
    expect(() => loadPackageConfig(filePath)).toThrow(/Invalid package config/);
  });

  it("allows an OSV-only section (no cpes)", () => {
    const filePath = path.join(FIXTURES_DIR, "vuln-osv-only.toml");
    fs.writeFileSync(
      filePath,
      withVuln(`[vulnerabilities]\nosv = { ecosystem = "PyPI", name = "uv" }\naliases = ["uv"]`),
    );
    const config = loadPackageConfig(filePath);
    expect(config.vulnerabilities?.cpes).toEqual([]);
    expect(config.vulnerabilities?.osv?.name).toBe("uv");
  });

  it("computeVulnInput normalizes aliases, marks the first cpe primary, and includes the package identity", () => {
    const filePath = path.join(FIXTURES_DIR, "vuln-input.toml");
    fs.writeFileSync(
      filePath,
      withVuln(`[vulnerabilities]
cpes = ["eclipse:temurin", "oracle:openjdk"]
aliases = ["  Adopt OpenJDK ", "JDK"]`),
    );
    const config = loadPackageConfig(filePath);
    const input = computeVulnInput(config)!;
    expect(input.cpes[0]).toEqual({
      cpe_vendor: "eclipse",
      cpe_product: "temurin",
      is_primary: true,
    });
    expect(input.cpes[1].is_primary).toBe(false);
    // normalized + package identity present
    expect(input.aliases).toContain("adopt openjdk");
    expect(input.aliases).toContain("jdk");
    expect(input.aliases).toContain("openjdk"); // from name
    expect(input.aliases).toContain("eclipse temurin openjdk"); // from display_name
  });

  it("computeVulnInput returns null when the section is absent", () => {
    const config = loadPackageConfig(path.join(FIXTURES_DIR, "uv-test.toml"));
    expect(computeVulnInput(config)).toBeNull();
  });
});

describe("loadAllPackages", () => {
  it("loads multiple valid TOML files from a directory", () => {
    const dir = path.join(FIXTURES_DIR, "multi");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "uv.toml"), VALID_UV_TOML);
    fs.writeFileSync(path.join(dir, "golang.toml"), VALID_GOLANG_TOML);

    const result = loadAllPackages(dir);
    expect(result.configs).toHaveLength(2);
    expect(result.errors).toHaveLength(0);
    const names = result.configs.map((c) => c.config.name).sort();
    expect(names).toEqual(["golang", "uv"]);
  });

  it("collects errors for invalid files without crashing", () => {
    const dir = path.join(FIXTURES_DIR, "mixed");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "good.toml"), VALID_UV_TOML);
    fs.writeFileSync(path.join(dir, "bad.toml"), 'name = "invalid"\ndisplay_name = "No discovery"');

    const result = loadAllPackages(dir);
    expect(result.configs).toHaveLength(1);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].error).toMatch(/Invalid package config/);
  });

  it("returns empty results for non-existent directory", () => {
    const result = loadAllPackages("/non/existent/path");
    expect(result.configs).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });
});
