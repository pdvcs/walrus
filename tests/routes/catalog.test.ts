import express from "express";
import request from "supertest";
import { describe, expect, it, vi } from "vitest";
import { createCatalogRouter, type CatalogRouteDeps } from "../../src/routes/catalog.js";
import type { VulnQueryResult } from "../../src/services/vuln-query.js";

/**
 * Everything an operator can do from the admin pages. None of it may appear in viewer output --
 * not as a button, not as a handler, not as a dead script that a console user could call.
 */
const ADMIN_ONLY_MARKERS = [
  "Sync Now",
  "Sync All",
  "syncPkg",
  "syncAll",
  "toggleEnabled",
  "deleteGroup",
  "deleteAllGroups",
  "redownload",
  "releaseNow",
  "revokeWaiver",
  "Release now",
  "Delete",
  "suppression-open",
  "Suppress",
  "Revoke",
  "Gate action",
  "/admin/v1/sync",
  "/admin/v1/vuln-suppressions",
  "/admin/v1/vuln-sync",
  "/admin/v1/vuln-backfill",
];

function expectNoAdminSurface(html: string): void {
  for (const marker of ADMIN_ONLY_MARKERS) {
    expect(html, `viewer page leaked admin marker "${marker}"`).not.toContain(marker);
  }
  // The only way into /admin/v1 from a public page is the nav's login link.
  const adminRefs = html.match(/\/admin\/v1[^"'\s<)]*/g) ?? [];
  for (const ref of adminRefs) {
    expect(ref, "unexpected /admin/v1 reference on a public page").toMatch(
      /^\/admin\/v1\/login\b|^\/admin\/v1\/$/,
    );
  }
}

function pkgRow(name: string, enabled = true) {
  return {
    name,
    display_name: name.toUpperCase(),
    vendor: `${name}-vendor`,
    description: null,
    website: `https://${name}.example.test`,
    config_hash: "",
    enabled,
    removed_at: null,
  };
}

function artifact(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    id: 1,
    version_id: 1,
    os: "linux",
    arch: "x86-64",
    filename: "cpython.tar.gz",
    gcs_path: "k",
    file_size: 1,
    checksum: null,
    checksum_type: null,
    upstream_url: "https://example.test/cpython.tar.gz",
    status: "available",
    error_message: null,
    download_started_at: null,
    download_completed_at: null,
    removed_at: null,
    created_at: new Date(),
    cooling_off_until: null,
    ...overrides,
  };
}

function depsFor(
  artifacts: ReturnType<typeof artifact>[],
  badges: Record<string, unknown> = {},
): CatalogRouteDeps {
  return {
    listConfiguredPackages: vi.fn().mockReturnValue(["python", "retired", "ghost"]),
    listEnabledPackages: vi.fn().mockResolvedValue([pkgRow("python")]),
    getPackage: vi.fn(async (name: string) =>
      name === "python" ? pkgRow("python") : name === "retired" ? pkgRow("retired", false) : null,
    ),
    listJobs: vi.fn().mockResolvedValue([]),
    listVersionGroupNamesForPackage: vi.fn().mockResolvedValue(["3.13"]),
    listVersionsInGroup: vi.fn().mockResolvedValue([{ id: 1, version: "3.13.15", is_lts: false }]),
    listArtifactsForVersionId: vi.fn().mockResolvedValue(artifacts),
    getPackageVulnBadges: vi.fn().mockResolvedValue({
      tracked: Object.keys(badges).length > 0,
      byVersion: badges,
    }),
    queryVulns: vi.fn(),
    getDataFreshness: vi.fn().mockResolvedValue({
      nvd_last_sync: "2026-10-30T10:00:00.000Z",
      kev_last_sync: null,
      osv_last_sync: null,
      cvss_last_sync: null,
    }),
    getSyncStatus: vi.fn().mockResolvedValue({
      nvd: { last_attempt: null, last_success: null, last_failure: null, last_ok: true },
      kev: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
      osv: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
      cvss: { last_attempt: null, last_success: null, last_failure: null, last_ok: null },
    }),
  } as unknown as CatalogRouteDeps;
}

function appFor(deps: CatalogRouteDeps, basePath = ""): express.Express {
  const app = express();
  app.use(basePath || "/", createCatalogRouter(deps, basePath));
  return app;
}

const GATED = { total: 1, critical: 1, high: 0, kev: 0, blocked: true };
const NOISY = { total: 2, critical: 0, high: 2, kev: 0, blocked: false };

describe("GET /packages", () => {
  it("lists enabled, configured packages and nothing else, without admin controls", async () => {
    const res = await request(appFor(depsFor([])))
      .get("/packages")
      .expect(200);
    expect(res.headers["content-type"]).toMatch(/html/);
    expect(res.text).toContain('href="/packages/python"');
    expect(res.text).toContain("python-vendor");
    // `retired` is configured but disabled; `ghost` is configured with no row at all.
    expect(res.text).not.toContain("retired");
    expect(res.text).not.toContain("ghost");
    expect(res.text).toContain('data-filter="P"');
    expectNoAdminSurface(res.text);
  });

  it("uses the public nav rather than the admin nav", async () => {
    const res = await request(appFor(depsFor([])))
      .get("/packages")
      .expect(200);
    expect(res.text).toContain("Site navigation");
    expect(res.text).not.toContain("Admin navigation");
    expect(res.text).not.toContain("nav-suppressions");
    expect(res.text).not.toContain('id="degraded-banner"');
    expect(res.text).not.toContain("health-degradation-ui");
    expect(res.text).toContain("— Walrus</title>");
  });

  it("is visibly the public view: day-scene logo and teal accent, never the admin logo", async () => {
    const app = appFor(depsFor([artifact()]));
    for (const page of ["/packages", "/packages/python", "/vulns"]) {
      const res = await request(app).get(page).expect(200);
      expect(res.text, page).toContain('src="/brand/logo"');
      expect(res.text, page).not.toContain("/brand/admin-logo");
      expect(res.text, page).toContain("border-top: 4px solid #0d9488");
    }
  });
});

describe("GET /packages/:name", () => {
  it("404s for a disabled package, an unconfigured row and an unknown name", async () => {
    const app = appFor(depsFor([]));
    for (const name of ["retired", "ghost", "nope"]) {
      const res = await request(app).get(`/packages/${name}`).expect(404);
      expect(res.headers["content-type"]).toMatch(/html/);
      expect(res.text).toContain("Package not found");
    }
  });

  it("links only the artifacts GET /download would serve", async () => {
    const deps = depsFor([
      artifact({ id: 1, os: "linux", arch: "x86-64", status: "available" }),
      artifact({ id: 2, os: "linux", arch: "arm64", status: "pending" }),
      artifact({ id: 3, os: "darwin", arch: "arm64", status: "failed" }),
      artifact({
        id: 4,
        os: "windows",
        arch: "x86-64",
        status: "available",
        cooling_off_until: new Date(Date.now() + 3 * 86_400_000),
      }),
    ]);
    const res = await request(appFor(deps)).get("/packages/python").expect(200);

    expect(res.text).toContain('href="/download/python/3.13.15/linux/x86-64"');
    for (const unservable of ["linux/arm64", "darwin/arm64", "windows/x86-64"]) {
      expect(res.text).not.toContain(`/download/python/3.13.15/${unservable}`);
    }
    // The cooling-off cell keeps its explanation even though it is not a link.
    expect(res.text).toContain("cooling-off");
    expect(res.text).toContain("available 20");
    expect(res.text).toContain('href="/packages"');
    expectNoAdminSurface(res.text);
  });

  it("does not link a download that the CVE gate blocks, and explains why", async () => {
    const deps = depsFor([artifact()], { "3.13.15": GATED });
    const res = await request(appFor(deps)).get("/packages/python").expect(200);

    expect(res.text).not.toContain("/download/python/3.13.15/linux/x86-64");
    expect(res.text).toContain("blocked: downloads return 403");
    expect(res.text).toContain('class="badge badge-blocked"');
    expectNoAdminSurface(res.text);
  });

  it("points vulnerability badges at the public /vulns page", async () => {
    const deps = depsFor([artifact()], { "3.13.15": NOISY });
    const res = await request(appFor(deps)).get("/packages/python").expect(200);

    expect(res.text).toContain('href="/vulns?product=python&version=3.13.15"');
    expect(res.text).not.toContain("/admin/v1/vulns");
  });

  it("never loads or renders waivers or job internals", async () => {
    const deps = depsFor([artifact()]);
    (deps.listJobs as ReturnType<typeof vi.fn>).mockResolvedValue([
      { id: 77, status: "completed", started_at: new Date(Date.now() - 3_600_000) },
    ]);
    const res = await request(appFor(deps)).get("/packages/python").expect(200);

    expect(res.text).toContain("Last synced");
    expect(res.text).not.toContain("/jobs/77");
    expect(res.text).not.toContain("waiver");
    expect(res.text).not.toContain('class="badge badge-completed"');
  });
});

function vulnResult(overrides: Partial<VulnQueryResult> = {}): VulnQueryResult {
  const item = (id: string, suppression: VulnQueryResult["vulns"][number]["suppression"]) => ({
    cve_id: id,
    severity: "CRITICAL",
    severity_source: "nvd",
    cvss_v3_score: 9.8,
    cvss_v4_score: null,
    cvss_v2_score: null,
    summary: null,
    affected: { range: "< 3.13.16", matched_because: "range" },
    fixed_in: "3.13.16",
    is_kev: false,
    sources: ["nvd"],
    references: [],
    suppression,
  });
  return {
    query: { product: "python", version: "3.13.15" },
    match: {
      resolved: true,
      product_slug: "python",
      display_name: "Python",
      confidence: 1,
      method: "exact",
      candidates: [],
    },
    vulns: [
      item("CVE-2026-0001", null),
      item("CVE-2026-0002", {
        id: 41,
        reason: "accepted risk",
        created_by: "alice-operator",
        package_name: "python",
        expires_at: "2027-01-01T00:00:00.000Z",
      }),
    ],
    counts: { total: 2, critical: 2, high: 0, medium: 0, low: 0, kev: 0 },
    data_freshness: {
      nvd_last_sync: null,
      kev_last_sync: null,
      osv_last_sync: null,
      cvss_last_sync: null,
    },
    disclaimer: "",
    ...overrides,
  } as VulnQueryResult;
}

describe("GET /vulns", () => {
  it("renders the lookup form and freshness chips with no product", async () => {
    const deps = depsFor([]);
    const res = await request(appFor(deps)).get("/vulns").expect(200);

    expect(deps.queryVulns).not.toHaveBeenCalled();
    expect(res.text).toContain('action="/vulns"');
    expect(res.text).toContain("Enter a product");
    expect(res.text).toContain("src-chip");
    // Autocomplete talks to the already-public search endpoint.
    expect(res.text).toContain("/api/v1/vulns/products/search");
    expectNoAdminSurface(res.text);
  });

  it("shows CVEs with the gate explanation but only the public slice of a suppression", async () => {
    const deps = depsFor([]);
    (deps.queryVulns as ReturnType<typeof vi.fn>).mockResolvedValue(vulnResult());
    const res = await request(appFor(deps))
      .get("/vulns?product=python&version=3.13.15")
      .expect(200);

    expect(deps.queryVulns).toHaveBeenCalledWith("python", "3.13.15");
    expect(res.text).toContain("CVE-2026-0001");
    // Unsuppressed critical row explains the 403; the suppressed one does not claim to block.
    expect(res.text).toContain("blocks at 9.8");
    expect(res.text.match(/blocks at 9\.8/g)).toHaveLength(1);
    expect(res.text).toContain("suppressed");
    expect(res.text).toContain("accepted risk");
    expect(res.text).toContain("expires 2027-01-01");
    expect(res.text).not.toContain("alice-operator");
    expect(res.text).not.toContain('data-id="41"');
    expect(res.text).toContain('href="/packages/python"');
    expectNoAdminSurface(res.text);
  });

  it("offers no package-page link when the product is not an enabled package", async () => {
    const deps = depsFor([]);
    (deps.queryVulns as ReturnType<typeof vi.fn>).mockResolvedValue(
      vulnResult({ match: { ...vulnResult().match, product_slug: "retired" } }),
    );
    const res = await request(appFor(deps)).get("/vulns?product=retired").expect(200);
    expect(res.text).not.toContain('href="/packages/retired"');
  });

  it("sends 'did you mean' suggestions to the public page", async () => {
    const deps = depsFor([]);
    (deps.queryVulns as ReturnType<typeof vi.fn>).mockResolvedValue(
      vulnResult({
        match: {
          resolved: false,
          product_slug: null,
          display_name: null,
          confidence: null,
          method: "none",
          candidates: [{ slug: "python", display_name: "Python", score: 0.8 }],
        } as unknown as VulnQueryResult["match"],
        vulns: [],
      }),
    );
    const res = await request(appFor(deps)).get("/vulns?product=pyton").expect(200);
    expect(res.text).toContain('href="/vulns?product=python"');
    expect(res.text).not.toContain("/admin/v1/vulns");
  });
});

describe("base path", () => {
  it("prefixes every internal link on every page", async () => {
    const deps = depsFor([artifact()], { "3.13.15": NOISY });
    (deps.queryVulns as ReturnType<typeof vi.fn>).mockResolvedValue(vulnResult());
    const app = appFor(deps, "/walrus");

    const pages = ["/walrus/packages", "/walrus/packages/python", "/walrus/vulns?product=python"];
    for (const page of pages) {
      const res = await request(app).get(page).expect(200);
      const hrefs = [...res.text.matchAll(/(?:href|action)="(\/[^"]*)"/g)].map((m) => m[1]);
      expect(hrefs.length).toBeGreaterThan(0);
      for (const href of hrefs) {
        expect(href, `${page}: unprefixed link ${href}`).toMatch(/^\/walrus(\/|$|\?)/);
      }
    }
  });
});
