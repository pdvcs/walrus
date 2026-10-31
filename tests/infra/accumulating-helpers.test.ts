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
 * WAL-97 recorded the leftover helpers as "a loaded gun": public, sitting in autocomplete beside
 * the streaming call, and reintroducing WAL-95 verbatim the moment anyone reached for one. They
 * were **deleted on 2026-09-01**, and `nvd-client.test.ts` now builds its own list from a fake
 * transport where accumulation is harmless.
 *
 * So this guard has two jobs, and they are different. It fails if `src/` grows a *call* to one —
 * which would now be a compile error, but only while the name stays deleted. And it fails if
 * anything *redefines* one, which is the way the hazard actually comes back: someone needs a
 * finished list, writes the obvious three-line wrapper, and every caller after them inherits
 * WAL-95 with nothing else failing.
 *
 * A grep rather than a type, because a type cannot describe the absence of a method nobody has
 * written yet.
 */
const ACCUMULATING = ["cvesForCpe", "cvesModifiedSince"] as const;

/**
 * Nothing is exempt any more. Both names were deleted from `nvd-client.ts`, and the prose in
 * `cvss-enrich.ts` that used to cite `cvesForCpe` now names the query it makes instead — so a
 * hit anywhere in `src/` is a genuine finding rather than a mention to skip past.
 */
const ALLOWED: string[] = [];

/**
 * Strip comments before matching. The guard is about code, and the files most likely to *say*
 * `cvesForCpe(...)` are precisely the ones explaining why it is gone — `nvd-client.ts` carries a
 * note where the methods used to be, and matching that made every assertion here fail on the
 * commit that deleted them. A guard that fires on its own tombstone teaches people to delete the
 * guard.
 */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
}

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
          new RegExp(`\\b${name}\\s*\\(`).test(
            stripComments(readFileSync(path.join(root, rel), "utf8")),
          ),
        );

      expect(
        callers,
        `${name} accumulates every page before writing anything — that is WAL-95/WAL-97. ` +
          `Use cvePages() and ingest per page instead.`,
      ).toEqual([]);
    });
  }

  for (const name of ACCUMULATING) {
    it(`${name} is not redefined anywhere in src/`, () => {
      // The realistic regression: not a call to something deleted, but someone re-adding the
      // three-line wrapper because they wanted a finished list. `NvdClient` must only ever
      // expose the streaming form.
      const definers = files
        .map((f) => path.relative(root, f))
        .filter((rel) =>
          new RegExp(
            `(async\\s+)?${name}\\s*(<[^>]*>)?\\s*\\(|${name}\\s*[:=]\\s*(async\\s*)?\\(`,
          ).test(stripComments(readFileSync(path.join(root, rel), "utf8"))),
        );

      expect(
        definers,
        `${name} is back. It drains every page into one array, which is exactly WAL-95 and ` +
          `WAL-97. Page with cvePages() and ingest per page; if a test needs a finished list, ` +
          `build it in the test.`,
      ).toEqual([]);
    });
  }
});
