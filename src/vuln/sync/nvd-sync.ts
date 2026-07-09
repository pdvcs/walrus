/**
 * NVD ingestion (ported from vulncheck `worker/nvdSync.ts`), keyed to walrus
 * packages. For each CVE: upsert `cves`, parse `configurations[].nodes[].cpeMatch[]`
 * via the CPE parser, join vendor/product against `package_cpes`, and rebuild
 * that CVE's `'nvd'` `cve_affects` rows. See plan §5, WAL-7.
 */
import { Pool } from "pg";
import { NvdClient, type NvdCveItem } from "./nvd-client.js";
import { parseCpe, buildMatchString } from "../cpe.js";
import {
  upsertCveFull,
  deleteAffectsForSource,
  insertAffects,
  AffectsInsert,
} from "../../db/queries/cves.js";
import { loadCpeLookup, listDistinctCpePairs } from "../../db/queries/package-aliases.js";
import { getSyncCursor, setSyncState } from "../../db/queries/vuln-sync-state.js";

export interface IngestCounts {
  cves: number;
  affects: number;
  skippedCpes: number;
}

/** Pick the best CVSS v3 metric (Primary preferred), tolerating NVD's variants. */
export function extractCvss(item: NvdCveItem): {
  score: number | null;
  vector: string | null;
  severity: string | null;
} {
  const metrics = item.cve.metrics ?? {};
  for (const key of ["cvssMetricV31", "cvssMetricV30"]) {
    const list = (metrics as Record<string, Array<Record<string, unknown>>>)[key];
    if (!list?.length) continue;
    const primary = list.find((m) => m["type"] === "Primary") ?? list[0];
    const data = primary["cvssData"] as
      | { baseScore?: number; vectorString?: string; baseSeverity?: string }
      | undefined;
    return {
      score: data?.baseScore ?? null,
      vector: data?.vectorString ?? null,
      severity: data?.baseSeverity ?? (primary["baseSeverity"] as string | undefined) ?? null,
    };
  }
  return { score: null, vector: null, severity: null };
}

/** Build cve_affects rows (source 'nvd') for the packages we track. */
export function extractAffects(
  item: NvdCveItem,
  lookup: Map<string, string[]>,
): { rows: AffectsInsert[]; skippedCpes: number } {
  const rows: AffectsInsert[] = [];
  const seen = new Set<string>();
  let skipped = 0;

  for (const conf of item.cve.configurations ?? []) {
    for (const node of conf.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable) continue;
        const parsed = parseCpe(m.criteria);
        if (!parsed || parsed.part !== "a") continue;
        const packageNames = lookup.get(`${parsed.vendor}:${parsed.product}`);
        if (!packageNames) {
          skipped++;
          continue;
        }

        const exactVersion =
          parsed.version !== "*" && parsed.version !== "-" ? parsed.version : null;
        const versionStart = m.versionStartIncluding ?? m.versionStartExcluding ?? null;
        const versionEnd = m.versionEndIncluding ?? m.versionEndExcluding ?? null;
        // Same criteria can appear in multiple nodes with different ranges, so
        // the dedupe key (and stored raw_cpe) includes the range.
        const rangeTag = [
          m.versionStartIncluding
            ? `>=${m.versionStartIncluding}`
            : m.versionStartExcluding
              ? `>${m.versionStartExcluding}`
              : "",
          m.versionEndIncluding
            ? `<=${m.versionEndIncluding}`
            : m.versionEndExcluding
              ? `<${m.versionEndExcluding}`
              : "",
        ]
          .filter(Boolean)
          .join(",");
        const rawCpe = rangeTag ? `${m.criteria}|${rangeTag}` : m.criteria;

        for (const packageName of packageNames) {
          const key = `${packageName}|${rawCpe}`;
          if (seen.has(key)) continue;
          seen.add(key);
          rows.push({
            cve_id: item.cve.id,
            package_name: packageName,
            version_start: versionStart,
            version_start_excl: Boolean(m.versionStartExcluding),
            version_end: versionEnd,
            version_end_excl: Boolean(m.versionEndExcluding),
            exact_version: exactVersion,
            fixed_in: m.versionEndExcluding ?? null,
            source: "nvd",
            raw_cpe: rawCpe,
          });
        }
      }
    }
  }
  return { rows, skippedCpes: skipped };
}

/** Upsert a batch of NVD CVE items and rebuild their 'nvd' affects rows, transactionally. */
export async function ingestCveItems(
  pool: Pool,
  items: NvdCveItem[],
  lookup?: Map<string, string[]>,
): Promise<IngestCounts> {
  const cpeLookup = lookup ?? (await loadCpeLookup(pool));
  const counts: IngestCounts = { cves: 0, affects: 0, skippedCpes: 0 };
  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    for (const item of items) {
      const cve = item.cve;
      const desc = cve.descriptions?.find((d) => d.lang === "en")?.value ?? null;
      const { score, vector, severity } = extractCvss(item);

      await upsertCveFull(client, {
        id: cve.id,
        published_at: cve.published ?? null,
        modified_at: cve.lastModified ?? null,
        cvss_v3_score: score,
        cvss_v3_vector: vector,
        severity,
        description: desc,
        raw: item,
      });
      counts.cves++;

      // Rebuild NVD-sourced affects rows for this CVE (modified CVEs may have
      // changed configurations; OSV rows are left untouched).
      await deleteAffectsForSource(client, cve.id, "nvd");
      const { rows, skippedCpes } = extractAffects(item, cpeLookup);
      counts.skippedCpes += skippedCpes;
      for (const r of rows) {
        await insertAffects(client, r);
        counts.affects++;
      }
    }
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
  return counts;
}

type Logger = (msg: string) => void;

/** Per-pair backfill using virtualMatchString (keeps the DB scoped to tracked packages). */
export async function backfillNvd(
  pool: Pool,
  nvd: NvdClient,
  opts: { since?: string; log?: Logger } = {},
): Promise<IngestCounts> {
  const log = opts.log ?? (() => {});
  const pairs = await listDistinctCpePairs(pool);
  const lookup = await loadCpeLookup(pool);
  const totals: IngestCounts = { cves: 0, affects: 0, skippedCpes: 0 };
  const extra: Record<string, string> = opts.since
    ? { pubStartDate: `${opts.since}T00:00:00.000Z` }
    : {};

  try {
    for (const pair of pairs) {
      const matchString = buildMatchString(pair.cpe_vendor, pair.cpe_product);
      log(`backfill: ${pair.cpe_vendor}:${pair.cpe_product} (${matchString})`);
      const items = await nvd.cvesForCpe(matchString, extra);
      const counts = await ingestCveItems(pool, items, lookup);
      log(
        `  ${items.length} CVEs → ${counts.affects} affects rows (${counts.skippedCpes} untracked CPEs skipped)`,
      );
      totals.cves += counts.cves;
      totals.affects += counts.affects;
      totals.skippedCpes += counts.skippedCpes;
    }
    await setSyncState(pool, "nvd-cve", new Date().toISOString(), true);
  } catch (err) {
    await setSyncState(pool, "nvd-cve", null, false);
    throw err;
  }
  return totals;
}

const MAX_WINDOW_MS = 119 * 24 * 3600 * 1000; // NVD caps lastMod windows at 120 days

/**
 * Incremental sync from the vuln_sync_state cursor. On a fresh DB (no cursor)
 * bootstraps a 119-day lookback window rather than erroring, so the /internal
 * trigger works before a full backfill (which remains the way to get history).
 * The cursor advances only on success.
 */
export async function incrementalNvdSync(
  pool: Pool,
  nvd: NvdClient,
  opts: { log?: Logger } = {},
): Promise<IngestCounts> {
  const log = opts.log ?? (() => {});
  const cursor = await getSyncCursor(pool, "nvd-cve");
  const now = new Date();
  const start = cursor ? new Date(cursor) : new Date(now.getTime() - MAX_WINDOW_MS);
  const end = new Date(Math.min(now.getTime(), start.getTime() + MAX_WINDOW_MS));

  try {
    const items = await nvd.cvesModifiedSince(start.toISOString(), end.toISOString());
    // A lastMod window returns EVERYTHING modified; keep only CVEs that touch a
    // tracked package (or that we already know about).
    const lookup = await loadCpeLookup(pool);
    const relevant = items.filter((item) => extractAffects(item, lookup).rows.length > 0);
    const counts = await ingestCveItems(pool, relevant, lookup);
    log(
      `incremental: ${items.length} modified CVEs in window, ${relevant.length} relevant, ${counts.affects} affects rows`,
    );
    await setSyncState(pool, "nvd-cve", end.toISOString(), true);
    return counts;
  } catch (err) {
    await setSyncState(pool, "nvd-cve", null, false);
    throw err;
  }
}
