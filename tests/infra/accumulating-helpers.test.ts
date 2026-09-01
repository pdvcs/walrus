import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

/**
 * WAL-95 and WAL-97 were the same defect twice: an `NvdClient` helper that concatenates every
 * page of a result into one array before anything is written, called from a path with no bound
 * on how much upstream returns. The first aborted `walrus-api` twice a day; the second sat on the
 * backfill job waiting for WAL-77 to reach it. Both were fixed by moving the caller to
 * `cvePages`, which streams.
 *
 * `cvesForCpe` and `cvesModifiedSince` still exist, because `nvd-client.test.ts` uses them to
 * exercise pagination, retry and rate-limiting behaviour against a fake transport — behaviour
 * worth testing, on methods no longer safe to call. WAL-97 recorded that as "a loaded gun": they
 * are public, their names are the obvious thing to reach for, and a future caller reintroduces
 * WAL-95 verbatim with no test failing.
 *
 * This is the guard for that. It is deliberately a grep rather than a type: the risk is someone
 * writing a new call site, and a grep is what notices one appearing.
 */
const ACCUMULATING = ["cvesForCpe", "cvesModifiedSince"] as const;

/** Where they are defined and documented — the definition is not a call site. */
const ALLOWED = ["src/vuln/sync/nvd-client.ts", "src/vuln/sync/cvss-enrich.ts"];

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return full.endsWith(".ts") ? [full] : [];
  });
}

describe("accumulating NVD helpers stay out of src/ (WAL-95, WAL-97)", () => {
  const root = process.cwd();
  const files = sourceFiles(path.join(root, "src"));

  it("finds source files to check at all", () => {
    // Without this the suite passes vacuously if the walk ever breaks.
    expect(files.length).toBeGreaterThan(50);
  });

  for (const name of ACCUMULATING) {
    it(`${name} has no caller in src/`, () => {
      const callers = files
        .map((f) => path.relative(root, f))
        .filter((rel) => !ALLOWED.includes(rel))
        .filter((rel) =>
          new RegExp(`\\b${name}\\s*\\(`).test(readFileSync(path.join(root, rel), "utf8")),
        );

      expect(
        callers,
        `${name} accumulates every page before writing anything — that is WAL-95/WAL-97. ` +
          `Use cvePages() and ingest per page instead.`,
      ).toEqual([]);
    });
  }

  it("the allowed files mention them only in prose or as declarations, not as calls", () => {
    // `cvss-enrich.ts` names `cvesForCpe` in a comment explaining why a by-id lookup is needed.
    // If that ever becomes a real call the exemption above would hide it, so check it directly.
    const enrich = readFileSync(path.join(root, "src/vuln/sync/cvss-enrich.ts"), "utf8");
    expect(/\bcvesForCpe\s*\(/.test(enrich)).toBe(false);
  });
});
