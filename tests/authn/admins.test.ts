import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAdminRoster, loadAdminRoster } from "../../src/authn/admins.js";

const temporaryDirectories: string[] = [];

afterEach(() => {
  for (const directory of temporaryDirectories.splice(0)) fs.rmSync(directory, { recursive: true });
});

describe("admin roster", () => {
  it("matches trimmed case and Unicode compatibility variants by default", () => {
    const roster = createAdminRoster(["Alice@example.com", "ＡＤＭＩＮ"]);
    expect(roster.has(" alice@EXAMPLE.com ")).toBe(true);
    expect(roster.has("admin")).toBe(true);
    expect(roster.has("bob@example.com")).toBe(false);
  });

  it("keeps case and Unicode distinct in exact mode while trimming", () => {
    const roster = createAdminRoster(["Alice", "ＡＤＭＩＮ"], "exact");
    expect(roster.has(" Alice ")).toBe(true);
    expect(roster.has("alice")).toBe(false);
    expect(roster.has("ADMIN")).toBe(false);
  });

  it("loads a strict non-empty TOML roster", () => {
    const file = fixture('admins = ["admin", "operator@example.com"]\n');
    expect(loadAdminRoster(file).subjects).toEqual(["admin", "operator@example.com"]);
    expect(() => loadAdminRoster(fixture("admins = []\n"))).toThrow("at least");
    expect(() => loadAdminRoster(fixture('admins = ["admin"]\nroles = []\n'))).toThrow(
      "Unrecognized key",
    );
    expect(() => loadAdminRoster(path.join(os.tmpdir(), "missing-walrus-admins.toml"))).toThrow(
      "Unable to read",
    );
  });

  it("rejects ambiguous duplicates after normalization", () => {
    expect(() => createAdminRoster(["Admin", "ＡＤＭＩＮ"])).toThrow("duplicate");
  });
});

function fixture(contents: string): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "walrus-admins-"));
  temporaryDirectories.push(directory);
  const file = path.join(directory, "admins.toml");
  fs.writeFileSync(file, contents);
  return file;
}
