/**
 * OSV cross-check (ported from vulncheck `worker/osvSync.ts`), keyed to walrus
 * packages. For each package with an OSV mapping, query api.osv.dev, upsert stub
 * cves rows for OSV-only CVEs, and insert cve_affects with source='osv' (deduped
 * by the unique constraint). See plan §5, WAL-8.
 */
import { Pool } from "pg";
import {
  upsertCveStub,
  deleteAffectsForPackageAndSource,
  insertAffects,
} from "../../db/queries/cves.js";
import { listPackagesWithOsv } from "../../db/queries/package-aliases.js";
import { setSyncState } from "../../db/queries/vuln-sync-state.js";
import { config } from "../../config/index.js";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  modified?: string;
  affected?: Array<{
    package?: { ecosystem?: string; name?: string };
    ranges?: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
    }>;
  }>;
}

export interface OsvSyncResult {
  packages: number;
  vulns: number;
  affectsUpserted: number;
  stubCves: number;
  skippedNoCve: number;
}

/** Query OSV for every vuln affecting a package (paginated). */
export async function queryOsvPackage(
  ecosystem: string,
  name: string,
  fetchFn: typeof fetch = fetch,
): Promise<OsvVuln[]> {
  const vulns: OsvVuln[] = [];
  let pageToken: string | undefined;
  do {
    const body: Record<string, unknown> = { package: { ecosystem, name } };
    if (pageToken) body["page_token"] = pageToken;
    const res = await fetchFn(OSV_QUERY_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(config.VULN_HTTP_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`OSV query failed: HTTP ${res.status} for ${ecosystem}/${name}`);
    const data = (await res.json()) as { vulns?: OsvVuln[]; next_page_token?: string };
    vulns.push(...(data.vulns ?? []));
    pageToken = data.next_page_token;
  } while (pageToken);
  return vulns;
}

interface EventPair {
  introduced?: string;
  fixed?: string;
  lastAffected?: string;
}

/** Fold an OSV event list into (introduced, fixed/last_affected) pairs. */
function eventPairs(
  events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>,
): EventPair[] {
  const pairs: EventPair[] = [];
  let current: EventPair | null = null;
  for (const e of events) {
    if (e.introduced !== undefined) {
      if (current) pairs.push(current); // open-ended previous pair
      current = { introduced: e.introduced };
    } else if (e.fixed !== undefined || e.last_affected !== undefined) {
      const pair = current ?? {};
      pair.fixed = e.fixed;
      pair.lastAffected = e.last_affected;
      pairs.push(pair);
      current = null;
    }
  }
  if (current) pairs.push(current);
  return pairs;
}

function cveIdOf(vuln: OsvVuln): string | null {
  if (/^CVE-\d{4}-\d{4,}$/.test(vuln.id)) return vuln.id;
  return vuln.aliases?.find((a) => /^CVE-\d{4}-\d{4,}$/.test(a)) ?? null;
}

/** Apply one package's OSV vulns to cves/cve_affects (source='osv'). */
export async function applyOsvVulns(
  pool: Pool,
  packageName: string,
  ecosystem: string,
  name: string,
  vulns: OsvVuln[],
): Promise<{ affectsUpserted: number; stubCves: number; skippedNoCve: number }> {
  let affectsUpserted = 0;
  let stubCves = 0;
  let skippedNoCve = 0;

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    // Rebuild this package's OSV affects so a re-run reflects removed advisories.
    await deleteAffectsForPackageAndSource(client, packageName, "osv");
    for (const vuln of vulns) {
      const cveId = cveIdOf(vuln);
      if (!cveId) {
        skippedNoCve++;
        continue;
      }

      // Stub cves row for OSV-only CVEs (NVD may lag); NVD ingestion will
      // overwrite the stub with full data when it catches up.
      stubCves += await upsertCveStub(client, {
        id: cveId,
        published_at: vuln.published ?? null,
        modified_at: vuln.modified ?? null,
        description: vuln.summary ?? vuln.details?.slice(0, 500) ?? null,
        raw: { osvStub: true, osv: vuln },
      });

      for (const aff of vuln.affected ?? []) {
        if (aff.package && (aff.package.ecosystem !== ecosystem || aff.package.name !== name))
          continue;
        for (const range of aff.ranges ?? []) {
          if (range.type !== "ECOSYSTEM" && range.type !== "SEMVER") continue;
          for (const pair of eventPairs(range.events)) {
            const versionStart =
              pair.introduced && pair.introduced !== "0" ? pair.introduced : null;
            const versionEnd = pair.fixed ?? pair.lastAffected ?? null;
            const versionEndExcl = pair.fixed !== undefined;
            const rawCpe = `osv:${vuln.id}|${pair.introduced ?? "0"}-${pair.fixed ?? pair.lastAffected ?? "*"}`;

            await insertAffects(client, {
              cve_id: cveId,
              package_name: packageName,
              version_start: versionStart,
              version_start_excl: false,
              version_end: versionEnd,
              version_end_excl: versionEndExcl,
              exact_version: null,
              fixed_in: pair.fixed ?? null,
              source: "osv",
              raw_cpe: rawCpe,
            });
            affectsUpserted++;
          }
        }
      }
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
  return { affectsUpserted, stubCves, skippedNoCve };
}

/** OSV cross-check for all packages with an OSV mapping. */
export async function osvSyncAll(
  pool: Pool,
  fetchFn: typeof fetch = fetch,
): Promise<OsvSyncResult> {
  const packages = await listPackagesWithOsv(pool);
  const result: OsvSyncResult = {
    packages: 0,
    vulns: 0,
    affectsUpserted: 0,
    stubCves: 0,
    skippedNoCve: 0,
  };
  try {
    for (const p of packages) {
      const vulns = await queryOsvPackage(p.osv_ecosystem, p.osv_name, fetchFn);
      const r = await applyOsvVulns(pool, p.package_name, p.osv_ecosystem, p.osv_name, vulns);
      result.packages++;
      result.vulns += vulns.length;
      result.affectsUpserted += r.affectsUpserted;
      result.stubCves += r.stubCves;
      result.skippedNoCve += r.skippedNoCve;
    }
    await setSyncState(pool, "osv", new Date().toISOString(), true);
  } catch (err) {
    await setSyncState(pool, "osv", null, false);
    throw err;
  }
  return result;
}
