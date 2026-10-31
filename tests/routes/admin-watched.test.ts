import { describe, it, expect } from "vitest";
import { renderWatchedPage } from "../../src/routes/admin-vulns.js";
import type { WatchedPackageRow } from "../../src/db/queries/packages.js";

function row(overrides: Partial<WatchedPackageRow> = {}): WatchedPackageRow {
  return {
    name: "requests",
    display_name: "Requests",
    vendor: "Python Software Foundation",
    osv_ecosystem: "PyPI",
    osv_name: "requests",
    cpes: ["python:requests"],
    vuln_backfill_completed_at: null,
    vuln_backfill_attempts: 0,
    vuln_backfill_last_error: null,
    osv_synced_at: new Date("2026-10-30T00:00:00Z"),
    latest_version: "2.34.0",
    latest_version_checked_at: new Date("2026-10-31T06:30:00Z"),
    latest_version_error: null,
    ...overrides,
  };
}

describe("renderWatchedPage (WAL-54)", () => {
  it("lists each watched package with its CPE pairs, OSV mapping and a lookup link", () => {
    const html = renderWatchedPage([row()], "");
    expect(html).toContain("Watched Packages");
    expect(html).toContain("<code>python:requests</code>");
    expect(html).toContain("PyPI: requests");
    expect(html).toContain("/admin/v1/vulns?product=requests");
    expect(html).toContain("not yet"); // never backfilled
  });

  it("shows the latest version and when it was checked", () => {
    const html = renderWatchedPage([row()], "");
    expect(html).toContain("<code>2.34.0</code>");
    expect(html).toContain("checked");
  });

  it("shows a failed or missing latest-version lookup rather than hiding it", () => {
    const html = renderWatchedPage(
      [row({ latest_version: null, latest_version_error: "pypi is down" })],
      "",
    );
    expect(html).toContain("not resolved");
    expect(html).toContain("pypi is down");
  });

  it("marks an OSV mapping that has never been synced", () => {
    expect(renderWatchedPage([row({ osv_synced_at: null })], "")).toContain("not synced yet");
    expect(renderWatchedPage([row()], "")).not.toContain("not synced yet");
  });

  it("shows the posture of the latest version with severity counts and the fix", () => {
    const html = renderWatchedPage(
      [row()],
      "",
      new Map([
        [
          "requests",
          {
            status: "vulnerable" as const,
            unknown_reasons: [],
            version: "2.34.0",
            upgrade_to: "2.40.0",
            counts: { total: 3, critical: 1, high: 1, medium: 1, low: 0, unrated: 0, kev: 0 },
          },
        ],
      ]),
    );
    expect(html).toContain("posture-vulnerable");
    expect(html).toContain("1 critical · 1 high · 1 medium · 0 low");
    expect(html).toContain("fix in 2.40.0");
    expect(html).toContain("/api/v1/packages/requests/posture");
  });

  it("explains an unknown posture instead of showing a clean-looking row", () => {
    const html = renderWatchedPage(
      [row()],
      "",
      new Map([
        [
          "requests",
          {
            status: "unknown" as const,
            unknown_reasons: ["coverage-incomplete" as const],
            version: "2.34.0",
            upgrade_to: null,
            counts: { total: 0, critical: 0, high: 0, medium: 0, low: 0, unrated: 0, kev: 0 },
          },
        ],
      ]),
    );
    expect(html).toContain("posture-unknown");
    expect(html).toContain("coverage-incomplete");
  });

  it("hides operator-only detail and links to the public lookup in viewer mode", () => {
    const html = renderWatchedPage(
      [
        row({
          vuln_backfill_last_error: "NVD 503",
          latest_version_error: "pypi down",
          vuln_backfill_attempts: 4,
        }),
      ],
      "",
      new Map(),
      "viewer",
    );
    expect(html).not.toContain("NVD 503");
    expect(html).not.toContain("pypi down");
    expect(html).not.toContain("Attempts");
    expect(html).not.toContain("/admin/v1/vulns");
    expect(html).toContain('href="/vulns?product=requests"');
    expect(html).toContain("Site navigation");
  });

  it("keeps the same detail for operators in admin mode", () => {
    const html = renderWatchedPage(
      [row({ vuln_backfill_last_error: "NVD 503", latest_version_error: "pypi down" })],
      "",
    );
    expect(html).toContain("NVD 503");
    expect(html).toContain("pypi down");
    expect(html).toContain("Attempts");
    expect(html).toContain("Admin navigation");
  });

  it("is a top-level admin nav item, marked active on this page", () => {
    const html = renderWatchedPage([row()], "");
    expect(html).toMatch(/<a href="\/admin\/v1\/watched" class="active">Watched<\/a>/);
  });

  it("says so when nothing is watched", () => {
    expect(renderWatchedPage([], "")).toContain("No watch-only packages");
  });

  it("honours the base path in its links", () => {
    expect(renderWatchedPage([row()], "/walrus")).toContain("/walrus/admin/v1/vulns?product=");
  });

  it("escapes values that came from a TOML file or a failed job", () => {
    const html = renderWatchedPage(
      [
        row({
          display_name: "<script>alert(1)</script>",
          vuln_backfill_last_error: "<img src=x onerror=alert(2)>",
        }),
      ],
      "",
    );
    expect(html).not.toContain("<script>alert(1)</script>");
    expect(html).not.toContain("<img src=x");
    expect(html).toContain("&lt;script&gt;");
  });
});
