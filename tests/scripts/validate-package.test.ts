import { describe, it, expect, beforeEach } from "vitest";
import { execSync } from "child_process";
import path from "path";
import fs from "fs";
import os from "os";
import { loadPackageConfig } from "../../src/services/package-registry.js";

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
