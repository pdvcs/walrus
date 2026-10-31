import { describe, it, expect } from "vitest";
import { getPosture, type PostureDeps } from "../../src/services/posture.js";
import type { AffectsWithCveRow } from "../../src/db/queries/cves.js";
import type { PackageRow } from "../../src/types/db.js";

function affects(over: Partial<AffectsWithCveRow> & { cve_id: string }): AffectsWithCveRow {
  return {
    version_start: null,
    version_start_excl: false,
    version_end: null,
    version_end_excl: true,
    exact_version: null,
    fixed_in: null,
    source: "nvd",
    version_na: false,
    severity: "HIGH",
    severity_source: "v3",
    cvss_v3_score: "7.5",
    cvss_v4_score: null,
    cvss_v2_score: null,
    description: "d",
    is_kev: false,
    raw: null,
    ...over,
  };
}

function pkg(over: Partial<PackageRow> = {}): PackageRow {
  return {
    name: "requests",
    display_name: "Requests",
    vendor: "PSF",
    description: null,
    website: null,
    config_hash: "",
    enabled: false,
    removed_at: null,
    watch_only: true,
    latest_version: "2.34.0",
    latest_version_checked_at: new Date("2026-10-31T06:30:00Z"),
    latest_version_error: null,
    osv_ecosystem: "PyPI",
    osv_name: "requests",
    vuln_backfill_completed_at: new Date("2026-10-30T00:00:00Z"),
    osv_synced_at: new Date("2026-10-30T00:00:00Z"),
    cve_version_extract: null,
    created_at: new Date(),
    updated_at: new Date(),
    ...over,
  };
}

function deps(
  rows: AffectsWithCveRow[],
  over: { pkg?: Partial<PackageRow> | null; cpes?: number; cached?: string | null } = {},
): PostureDeps {
  const row = over.pkg === null ? null : pkg(over.pkg);
  return {
    getPackage: async () => row,
    countCpes: async () => over.cpes ?? 1,
    newestCachedVersion: async () => over.cached ?? null,
    query: {
      resolvePackage: async (q: string) =>
        ({
          resolved: true,
          slug: q,
          displayName: "Requests",
          confidence: 1,
          method: "slug-exact",
          candidates: [],
        }) as never,
      listAffectsForPackage: async () => rows,
      getDataFreshness: async () => ({
        nvd_last_sync: null,
        kev_last_sync: null,
        osv_last_sync: null,
        cvss_last_sync: null,
      }),
      logUnresolved: async () => undefined,
    },
  };
}

describe("getPosture (WAL-54)", () => {
  it("returns null for an unknown package", async () => {
    expect(await getPosture(deps([], { pkg: null }), "nope", "1.0.0")).toBeNull();
  });

  it("is clean only when sources were read and no advisory matches", async () => {
    const rows = [affects({ cve_id: "CVE-1", version_end: "2.0.0", fixed_in: "2.0.0" })];
    const p = await getPosture(deps(rows), "requests", "2.34.0");
    expect(p!.status).toBe("clean");
    expect(p!.unknown_reasons).toEqual([]);
    expect(p!.counts.total).toBe(0);
    expect(p!.vulns).toEqual([]);
    expect(p!.coverage).toEqual({ nvd: "complete", osv: "complete" });
  });

  it("is vulnerable with severity counts, a worst-first list and the fix to move to", async () => {
    const rows = [
      affects({ cve_id: "CVE-A", severity: "MEDIUM", version_end: "2.31.0", fixed_in: "2.31.0" }),
      affects({ cve_id: "CVE-B", severity: "CRITICAL", version_end: "2.33.0", fixed_in: "2.33.0" }),
      affects({ cve_id: "CVE-C", severity: null, version_end: "2.40.0", fixed_in: "2.40.0" }),
      affects({ cve_id: "CVE-D", severity: "LOW", version_end: "2.0.0", fixed_in: "2.0.0" }),
    ];
    const p = await getPosture(deps(rows), "requests", "2.30.0");
    expect(p!.status).toBe("vulnerable");
    // CVE-D's range ends before 2.30.0, so it must not be counted.
    expect(p!.counts).toMatchObject({ total: 3, critical: 1, medium: 1, unrated: 1, low: 0 });
    expect(p!.vulns.map((v) => v.cve_id)).toEqual(["CVE-B", "CVE-A", "CVE-C"]);
    expect(p!.upgrade_to).toBe("2.40.0");
    expect(p!.unfixed).toBe(0);
    expect(p!.version_source).toBe("requested");
  });

  it("gives no upgrade target when any matching advisory has no known fix", async () => {
    const rows = [
      affects({ cve_id: "CVE-A", version_end: "2.40.0", fixed_in: "2.40.0" }),
      affects({ cve_id: "CVE-B", version_end: "2.40.0", version_end_excl: false, fixed_in: null }),
    ];
    const p = await getPosture(deps(rows), "requests", "2.30.0");
    expect(p!.status).toBe("vulnerable");
    expect(p!.unfixed).toBe(1);
    expect(p!.upgrade_to).toBeNull();
  });

  it("defaults to a watch package's latest version", async () => {
    const rows = [affects({ cve_id: "CVE-A", version_end: "3.0.0", fixed_in: "3.0.0" })];
    const p = await getPosture(deps(rows), "requests");
    expect(p!.version).toBe("2.34.0");
    expect(p!.version_source).toBe("latest");
    expect(p!.is_latest).toBe(true);
    expect(p!.status).toBe("vulnerable");
  });

  it("defaults to the newest cached version for a served package", async () => {
    const p = await getPosture(
      deps([], {
        pkg: { watch_only: false, enabled: true, latest_version: null },
        cached: "1.9.0",
      }),
      "requests",
    );
    expect(p!.version).toBe("1.9.0");
    expect(p!.version_source).toBe("latest");
  });

  it("is unknown, not clean, when there is no version to assess", async () => {
    const p = await getPosture(deps([], { pkg: { latest_version: null } }), "requests");
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toContain("no-version");
    expect(p!.version).toBeNull();
    expect(p!.vulns).toEqual([]); // never every advisory "matching" an absent version
  });

  it("is unknown, not clean, while a configured source has not been read", async () => {
    const p = await getPosture(deps([], { pkg: { osv_synced_at: null } }), "requests", "2.34.0");
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toEqual(["coverage-incomplete"]);
    expect(p!.coverage).toEqual({ nvd: "complete", osv: "pending" });
  });

  it("stays vulnerable despite incomplete coverage: more data can only add to it", async () => {
    const rows = [affects({ cve_id: "CVE-A", version_end: "3.0.0", fixed_in: "3.0.0" })];
    const p = await getPosture(deps(rows, { pkg: { osv_synced_at: null } }), "requests", "2.0.0");
    expect(p!.status).toBe("vulnerable");
    expect(p!.unknown_reasons).toContain("coverage-incomplete");
  });

  it("is unknown for a package with no CPE pairs and no OSV mapping", async () => {
    const p = await getPosture(
      deps([], { cpes: 0, pkg: { osv_ecosystem: null, osv_name: null } }),
      "requests",
      "2.34.0",
    );
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toContain("not-tracked");
    expect(p!.coverage).toEqual({ nvd: "not-configured", osv: "not-configured" });
  });

  it("treats an unparseable version as unknown and keeps its advisories out of the counts", async () => {
    const rows = [affects({ cve_id: "CVE-A", version_end: "3.0.0", fixed_in: "3.0.0" })];
    const p = await getPosture(deps(rows), "requests", "not a version");
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toContain("version-unparseable");
    expect(p!.counts.total).toBe(0);
    expect(p!.vulns.every((v) => !v.confirmed)).toBe(true);
  });

  it("lists an advisory whose range names no version without counting it", async () => {
    const rows = [affects({ cve_id: "CVE-NA", version_na: true })];
    const p = await getPosture(deps(rows), "requests", "2.34.0");
    expect(p!.status).toBe("unknown");
    expect(p!.unknown_reasons).toEqual(["inconclusive-ranges"]);
    expect(p!.vulns).toHaveLength(1);
    expect(p!.vulns[0].confirmed).toBe(false);
    expect(p!.counts.total).toBe(0);
  });

  it("flags a version older than the latest", async () => {
    const p = await getPosture(deps([]), "requests", "2.30.0");
    expect(p!.is_latest).toBe(false);
    expect(p!.latest_version).toBe("2.34.0");
  });
});
