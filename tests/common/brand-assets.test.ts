import fs from "fs";
import os from "os";
import path from "path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { isValidLogoRef, logoRefProblem, resolveLogoFile } from "../../src/common/brand-assets.js";

describe("logoRefProblem / isValidLogoRef", () => {
  it.each([
    "src/static/applogo.jpg",
    "config/my-logo.png",
    "./config/logo.PNG",
    "assets/brand/logo.webp",
    "a/b/../logo.gif",
  ])("accepts the in-repo image path %s", (ref) => {
    expect(logoRefProblem(ref)).toBeNull();
    expect(isValidLogoRef(ref)).toBe(true);
  });

  it.each([
    "http://example.com/logo.png",
    "https://example.com/logo.png",
    "HTTPS://example.com/logo.png",
    "//cdn.example.com/logo.png",
    "file:///etc/logo.png",
    "data:image/png;base64,AAAA",
    "ftp://example.com/logo.png",
  ])("rejects the URL %s", (ref) => {
    expect(logoRefProblem(ref)).toMatch(/not a URL/);
    expect(isValidLogoRef(ref)).toBe(false);
  });

  it.each(["/etc/logo.png", "\\share\\logo.png"])("rejects the absolute path %s", (ref) => {
    expect(logoRefProblem(ref)).toMatch(/relative to the application root/);
  });

  it.each(["../logo.png", "config/../../logo.png", ".."])(
    "rejects %s, which escapes the application root",
    (ref) => {
      expect(logoRefProblem(ref)).toMatch(/inside the application root/);
    },
  );

  it.each(["config/logo", "config/logo.svg", "config/logo.txt", "config/logo.png.exe"])(
    "rejects %s, which is not a supported image type",
    (ref) => {
      expect(logoRefProblem(ref)).toMatch(/must be an image file/);
    },
  );
});

describe("resolveLogoFile", () => {
  let root: string;
  let outside: string;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "walrus-logo-root-")));
    outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "walrus-logo-out-")));
    fs.mkdirSync(path.join(root, "config"));
    fs.writeFileSync(path.join(root, "config", "logo.png"), Buffer.alloc(16));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
    fs.rmSync(outside, { recursive: true, force: true });
  });

  it("returns the absolute real path of an existing image", () => {
    expect(resolveLogoFile("WALRUS_LOGO", "config/logo.png", root)).toBe(
      path.join(root, "config", "logo.png"),
    );
  });

  it("names the variable and the reference when the file is missing", () => {
    expect(() => resolveLogoFile("WALRUS_ADMIN_LOGO", "config/nope.png", root)).toThrow(
      /WALRUS_ADMIN_LOGO "config\/nope\.png" does not exist/,
    );
  });

  it("refuses a URL even though the check runs again at boot", () => {
    expect(() => resolveLogoFile("WALRUS_LOGO", "https://example.com/l.png", root)).toThrow(
      /not a URL/,
    );
  });

  it("refuses a directory that happens to look like an image", () => {
    fs.mkdirSync(path.join(root, "config", "dir.png"));
    expect(() => resolveLogoFile("WALRUS_LOGO", "config/dir.png", root)).toThrow(/not a file/);
  });

  it("refuses a symlink that points outside the root", () => {
    fs.writeFileSync(path.join(outside, "secret.png"), Buffer.alloc(16));
    fs.symlinkSync(path.join(outside, "secret.png"), path.join(root, "config", "link.png"));
    expect(() => resolveLogoFile("WALRUS_LOGO", "config/link.png", root)).toThrow(
      /resolves outside the application root/,
    );
  });

  it("allows a symlink that stays inside the root", () => {
    fs.symlinkSync(path.join(root, "config", "logo.png"), path.join(root, "config", "alias.png"));
    expect(resolveLogoFile("WALRUS_LOGO", "config/alias.png", root)).toBe(
      path.join(root, "config", "logo.png"),
    );
  });

  it("refuses a file too large to load on every page", () => {
    fs.writeFileSync(path.join(root, "config", "big.png"), Buffer.alloc(1024 * 1024 + 1));
    expect(() => resolveLogoFile("WALRUS_LOGO", "config/big.png", root)).toThrow(/limit is/);
  });
});

describe("WALRUS_LOGO / WALRUS_ADMIN_LOGO config", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
    vi.resetModules();
  });

  async function loadConfigWith(env: Record<string, string>) {
    vi.resetModules();
    for (const [k, v] of Object.entries(env)) vi.stubEnv(k, v);
    return import("../../src/config/index.js");
  }

  it("defaults to the bundled day and night logos", async () => {
    const { config } = await loadConfigWith({});
    expect(config.WALRUS_LOGO).toBe("src/static/applogo.jpg");
    expect(config.WALRUS_ADMIN_LOGO).toBe("src/static/applogo-admin.jpg");
  });

  it("takes an in-repo path from the environment", async () => {
    const { config } = await loadConfigWith({
      WALRUS_LOGO: " config/acme.png ",
      WALRUS_ADMIN_LOGO: "config/acme-admin.png",
    });
    expect(config.WALRUS_LOGO).toBe("config/acme.png");
    expect(config.WALRUS_ADMIN_LOGO).toBe("config/acme-admin.png");
  });

  it.each([
    ["WALRUS_LOGO", "https://example.com/logo.png"],
    ["WALRUS_ADMIN_LOGO", "http://example.com/logo.png"],
    ["WALRUS_LOGO", "../outside.png"],
    ["WALRUS_ADMIN_LOGO", "config/logo.svg"],
    ["WALRUS_LOGO", "   "],
  ])("refuses to start when %s is %j", async (name, value) => {
    const exit = vi.spyOn(process, "exit").mockImplementation((() => {
      throw new Error("process.exit");
    }) as never);
    vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(loadConfigWith({ [name]: value })).rejects.toThrow("process.exit");
    expect(exit).toHaveBeenCalledWith(1);
  });
});
