import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { execSync } from "child_process";
import path from "path";
import fs from "fs";
import os from "os";
import { setupServer } from "msw/node";
import { http, HttpResponse } from "msw";
import { loadPackageConfig } from "../../src/services/package-registry.js";
import { validatePackage } from "../../scripts/validate-package.js";

const ROOT = path.join(process.cwd());
const VALIDATE_CMD = `npx tsx ${path.join(ROOT, "scripts/validate-package.ts")}`;
const ENV = {
  ...process.env,
  NODE_ENV: "test",
  LOG_LEVEL: "warn",
  PORT: "8080",
  STORAGE_BACKEND: "local",
};

describe("validate-package CLI", () => {
  let tmpDir: string;
  let tomlPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-validate-test-"));
    tomlPath = path.join(tmpDir, "mytool.toml");
    fs.writeFileSync(
      tomlPath,
      `
name = "mytool"
display_name = "My Tool"
vendor = "Acme"

[discovery]
type = "github-releases"
repo = "acme/mytool"
tag_pattern = "^(\\\\d+\\\\.\\\\d+\\\\.\\\\d+)$"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+\\\\.\\\\d+)"
lts_support = false

[retention]
versions_per_group = 2

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "unknown-linux-gnu"
arch_upstream = "x86_64"
extension = "tar.gz"
filename_template = "mytool-{arch}-{os}.{ext}"
`,
    );
  });

  it("validates a single valid TOML file successfully", () => {
    // Mock fetch globally at the process level via env — instead we use
    // a real-network-free test by providing a file the validator can stub.
    // Since vitest doesn't share globals with child processes, we instead
    // run a quick programmatic test of the module functions directly.

    const config = loadPackageConfig(tomlPath);
    expect(config.name).toBe("mytool");
    expect(config.discovery.type).toBe("github-releases");
  });

  it("exits with code 1 for invalid TOML", () => {
    const badPath = path.join(tmpDir, "bad.toml");
    fs.writeFileSync(badPath, 'name = "bad"\ndisplay_name = "Bad"');

    let threw = false;
    try {
      execSync(`${VALIDATE_CMD} ${badPath}`, { env: ENV, stdio: "pipe" });
    } catch (err) {
      threw = true;
      const out = (err as { stdout: Buffer }).stdout?.toString() ?? "";
      expect(out).toMatch(/Schema validation failed|Invalid package config/);
    }
    expect(threw).toBe(true);
  });

  it("prints resolved vulnerability metadata when a [vulnerabilities] section is present", () => {
    const vulnPath = path.join(tmpDir, "withvuln.toml");
    fs.writeFileSync(
      vulnPath,
      `
name = "mytool"
display_name = "My Tool"
vendor = "Acme"

[discovery]
type = "github-releases"
repo = "acme/mytool"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+\\\\.\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "unknown-linux-gnu"
arch_upstream = "x86_64"
extension = "tar.gz"
filename_template = "mytool-{arch}-{os}.{ext}"

[vulnerabilities]
cpes = ["acme:mytool"]
osv = { ecosystem = "PyPI", name = "mytool" }
aliases = ["mytool", "my tool"]
`,
    );
    // Discovery will fail on the fake repo, but the vuln metadata block is printed
    // before discovery errors abort — capture stdout regardless of exit code.
    let out = "";
    try {
      out = execSync(`${VALIDATE_CMD} ${vulnPath}`, { env: ENV, stdio: "pipe" }).toString();
    } catch (err) {
      out = (err as { stdout: Buffer }).stdout?.toString() ?? "";
    }
    expect(out).toMatch(/Vulnerability tracking enabled/);
    expect(out).toMatch(/acme:mytool \(primary\)/);
    expect(out).toMatch(/PyPI\/mytool/);
  });

  it("exits with code 0 for no packages directory (graceful)", () => {
    const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-empty-"));
    // No TOML files — the CLI should exit 0 with a warning
    try {
      const out = execSync(`${VALIDATE_CMD}`, {
        env: { ...ENV, PWD: emptyDir },
        cwd: emptyDir,
        stdio: "pipe",
      }).toString();
      expect(out).toMatch(/No package configs found|validated successfully/);
    } finally {
      fs.rmSync(emptyDir, { recursive: true, force: true });
    }
  });
});

describe("validate-package CLI — transform exercise (WAL-59)", () => {
  const server = setupServer();
  let tmpDir: string;

  const FIXTURE = fs.readFileSync(
    path.join(process.cwd(), "tests/fixtures/transform-basic.tar.bz2"),
  );
  const FIXTURE_DIGEST = (() => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { createHash } = require("crypto") as typeof import("crypto");
    return createHash("sha256").update(FIXTURE).digest("hex");
  })();

  function writeToml(requirePaths: string[]): string {
    const tomlPath = path.join(tmpDir, "transformed.toml");
    fs.writeFileSync(
      tomlPath,
      `
name = "transformed"
display_name = "Transformed"
vendor = "Acme"

[discovery]
type = "github-releases"
repo = "acme/transformed"
tag_pattern = "^v(\\\\d+\\\\.\\\\d+\\\\.\\\\d+)$"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+\\\\.\\\\d+)"
lts_support = false

[[platforms]]
os = "windows"
arch = "x86-64"
os_upstream = "windows"
arch_upstream = "x64"
extension = "tar.bz2"
filename_template = "tool-{version}-64-bit.tar.bz2"

  [platforms.transform]
  type = "tar-bz2-to-zip"
  extension = "zip"
  filename_template = "tool-{version}-{os}-{arch}.zip"
  require_paths = [${requirePaths.map((p) => `"${p}"`).join(", ")}]
`,
    );
    return tomlPath;
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-validate-transform-"));
    server.listen({ onUnhandledRequest: "error" });
    server.use(
      http.get("https://api.github.com/repos/acme/transformed/releases", () =>
        HttpResponse.json([
          {
            tag_name: "v1.0.0",
            prerelease: false,
            draft: false,
            published_at: "2026-08-01T00:00:00Z",
            assets: [
              {
                name: "tool-1.0.0-64-bit.tar.bz2",
                browser_download_url:
                  "https://github.com/acme/transformed/releases/download/v1.0.0/tool-1.0.0-64-bit.tar.bz2",
                size: FIXTURE.length,
                digest: `sha256:${FIXTURE_DIGEST}`,
              },
            ],
          },
        ]),
      ),
      http.get(
        "https://github.com/acme/transformed/releases/download/v1.0.0/tool-1.0.0-64-bit.tar.bz2",
        () => new HttpResponse(new Uint8Array(FIXTURE)),
      ),
      http.head(
        "https://github.com/acme/transformed/releases/download/v1.0.0/tool-1.0.0-64-bit.tar.bz2",
        () => new HttpResponse(null, { headers: { "content-length": String(FIXTURE.length) } }),
      ),
    );
  });

  afterEach(() => {
    server.close();
    vi.restoreAllMocks();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("runs the transform for real and reports entries, output, digest, and gate hits", async () => {
    const tomlPath = writeToml(["cmd/git.exe", "usr/bin/bash.exe"]);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });

    const ok = await validatePackage(tomlPath, { online: false, transform: true });

    expect(ok).toBe(true);
    const joined = logs.join("\n");
    expect(joined).toMatch(/Transform exercise \(1\.0\.0 windows\/x86-64\)/);
    expect(joined).toMatch(/Entries: 3/);
    expect(joined).toMatch(/Output: \d+(\.\d+)? MB, sha256 [0-9a-f]{64}/);
    expect(joined).toMatch(/require_paths: cmd\/git\.exe/);
    expect(joined).toMatch(/require_paths: usr\/bin\/bash\.exe/);
  });

  it("a failing gate reports failure naming the cause", async () => {
    const tomlPath = writeToml(["cmd/git.exe", "usr/bin/no-such.exe"]);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });

    const ok = await validatePackage(tomlPath, { online: false, transform: true });

    expect(ok).toBe(false);
    expect(logs.join("\n")).toMatch(/transform problem\(s\)/);
    expect(logs.join("\n")).toMatch(/transform failed/);
    expect(logs.join("\n")).toMatch(/missing required path\(s\): usr\/bin\/no-such\.exe/);
  });

  it("without --transform the config still validates, with a hint that the exercise was skipped", async () => {
    const tomlPath = writeToml(["cmd/git.exe"]);
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });

    const ok = await validatePackage(tomlPath, { online: false, transform: false });

    expect(ok).toBe(true);
    const joined = logs.join("\n");
    expect(joined).toMatch(/pass --transform to exercise it/);
    expect(joined).not.toMatch(/Entries:/);
  });

  it("a config with no transform block behaves exactly as today", async () => {
    const tomlPath = path.join(tmpDir, "plain.toml");
    fs.writeFileSync(
      tomlPath,
      `
name = "plain"
display_name = "Plain"
vendor = "Acme"

[discovery]
type = "github-releases"
repo = "acme/transformed"
tag_pattern = "^v(\\\\d+\\\\.\\\\d+\\\\.\\\\d+)$"

[versioning]
type = "semver"
version_group_extract = "^(\\\\d+)"
lts_support = false

[[platforms]]
os = "linux"
arch = "x86-64"
os_upstream = "linux"
arch_upstream = "x64"
extension = "tar.gz"
filename_template = "tool-{version}-linux-x64.tar.gz"
`,
    );
    // This filename matches no asset — discovery resolves no artifacts for it, which is
    // today's behavior (a warning); no transform exercise may run.
    const logs: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    });

    const ok = await validatePackage(tomlPath, { online: false, transform: true });

    const joined = logs.join("\n");
    expect(joined).not.toMatch(/Transform exercise/);
    expect(ok).toBe(true);
  });
});
